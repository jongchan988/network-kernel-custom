#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/ctype.h>

#define AUTH_PREFIX "Authorization: Basic "
#define EXPECTED_USERNAME "AL1000"
#define EXPECTED_PASSWORD "0001020304050607FFFFFFFFFFFFFFFFFFFFFFFF"

static struct nf_hook_ops nfho;

// Base64 인코딩 테이블 및 디코딩 테이블 생성 함수
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

// 디코딩 테이블 생성
void build_decoding_table(void) { // 함수 원형에 void 추가
    int i; // for 루프 바깥에서 변수 선언
    decoding_table = kmalloc(256, GFP_KERNEL);
    for (i = 0; i < 64; i++) // for 루프 변수 선언 수정
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

// Base64 디코딩 함수
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = kmalloc(*output_length, GFP_KERNEL);
    if (decoded_data == NULL) return NULL;

    int i, j; // for 루프 바깥에서 변수 선언
    for (i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];

        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

// 문자열 비교 함수
static int compare_credentials(const char *decoded_value) {
    char *expected_value = EXPECTED_USERNAME ":" EXPECTED_PASSWORD;
    return strcmp(decoded_value, expected_value) == 0;
}

// Netfilter hook 함수
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sk_buff *skb_copy;
    char *data;
    char *auth_header;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcph = tcp_hdr(skb);
    if (ntohs(tcph->dest) != 80) {
        return NF_ACCEPT;
    }

    skb_copy = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb), GFP_ATOMIC);
    if (!skb_copy) {
        return NF_ACCEPT;
    }

    data = skb_copy->data + (iph->ihl * 4) + (tcph->doff * 4);

    auth_header = strstr(data, AUTH_PREFIX);
    if (auth_header) {
        auth_header += strlen(AUTH_PREFIX);

    	// Base64 인코딩된 인증 정보에서 '\r' 문자를 찾아서 '\0'로 대체하여 필요한 데이터만 남김
    	if (strchr(auth_header, '\r')) {
        	*strchr(auth_header, '\r') = '\0';
    	}
	printk(KERN_WARNING "auth_header: %s\n", auth_header);
        size_t decoded_len;
        unsigned char *decoded_value = base64_decode(auth_header, strlen(auth_header), &decoded_len);

        if (!decoded_value) {
            printk(KERN_WARNING "Invalid Base64 in Authorization header\n");
            kfree_skb(skb_copy);
            return NF_DROP; // Base64 디코딩 실패 시 드롭
        }

        decoded_value[decoded_len] = '\0'; // null-terminate the string

        // Credentials 비교
        if (compare_credentials((char *)decoded_value)) {
            printk(KERN_INFO "Authorization success: %s\n", decoded_value);
        } else {
            printk(KERN_WARNING "Authorization failed: %s\n", decoded_value);
            kfree(decoded_value);
            kfree_skb(skb_copy);
            return NF_DROP; // 인증 실패 시 드롭
        }

        kfree(decoded_value);
    }

    kfree_skb(skb_copy);
    return NF_ACCEPT;
}

// 모듈 초기화
static int __init init_nf_hook(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    build_decoding_table();
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "OCPP Netfilter module loaded.\n");
    return 0;
}

// 모듈 종료
static void __exit cleanup_nf_hook(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    if (decoding_table) kfree(decoding_table);
    printk(KERN_INFO "OCPP Netfilter module unloaded.\n");
}

module_init(init_nf_hook);
module_exit(cleanup_nf_hook);

MODULE_LICENSE("GPL");

