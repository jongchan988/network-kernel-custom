#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/jhash.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/errno.h>
#include <net/netfilter/ocpp_key_tb.h>

#define HASH_ALGO "sha256"
#define PROC_FILENAME "key_mgmt"

extern struct hlist_head key_table[OCPP_KEY_MGMT_HASH_TABLE_SIZE];


// 키 등록 함수
static ssize_t key_register(const char *user_key) {
    struct auth_key *key, *new_key;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    size_t key_len = strlen(user_key);
    char hash_output[32]; // SHA-256 해시 결과 저장
    int ret;

    // SHA-256 해시 계산을 위한 crypto API 초기화
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate hash algorithm: sha256\n");
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    // 입력 키에 대해 SHA-256 해시 계산
    ret = crypto_shash_digest(desc, user_key, key_len, hash_output);
    if (ret < 0) {
        printk(KERN_ERR "Hash calculation failed: %d\n", ret);
        kfree(desc);
        crypto_free_shash(tfm);
        return ret;
    }

    crypto_free_shash(tfm);
    kfree(desc);

    // 중복 검사: 해시 값을 기준으로 확인
    hash_for_each_possible(key_table, key, hnode, *(u32 *)hash_output) {
        if (memcmp(key->key, hash_output, 32) == 0) { // 해시 값 비교
            printk(KERN_WARNING "Duplicate key detected (hash): %s\n", user_key);
            return -EEXIST; // 중복 키는 -EEXIST 반환
        }
    }

    // 새 키 등록
    new_key = kmalloc(sizeof(*new_key), GFP_KERNEL);
    if (!new_key)
        return -ENOMEM;

    // 해시 값 저장 (바이너리 형태)
    new_key->key = kmalloc(32, GFP_KERNEL); // SHA-256 해시 결과 크기
    if (!new_key->key) {
        kfree(new_key);
        return -ENOMEM;
    }
    memcpy(new_key->key, hash_output, 32); // 해시 값을 복사하여 저장

    hash_add(key_table, &new_key->hnode, *(u32 *)hash_output); // 해시 테이블에 추가
    printk(KERN_INFO "Key registered successfully (hash): %s\n", user_key);

    return key_len;
}


// 키 삭제 함수

// 키 삭제 함수
static ssize_t key_remove(const char *user_key) {
    struct auth_key *key;
    struct hlist_node *tmp;
    size_t key_len = strlen(user_key);

    // "all" 명령 처리
    if (strcmp(user_key, "all") == 0) {
        int bkt; // 해시 테이블의 버킷 인덱스
        // 해시 테이블 순회
        hash_for_each_safe(key_table, bkt, tmp, key, hnode) {
            hash_del(&key->hnode); // 해시 테이블에서 삭제
            kfree(key->key);       // 메모리 해제
            kfree(key);
        }
        printk(KERN_INFO "All keys removed successfully.\n");
        return 0; // 성공적으로 삭제
    }

    // 특정 키 삭제
    char hash_output[32]; // SHA-256 해시 결과 저장
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    // SHA-256 해시 계산을 위한 crypto API 초기화
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate hash algorithm for removal: sha256\n");
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    // 입력 키에 대해 SHA-256 해시 계산
    ret = crypto_shash_digest(desc, user_key, key_len, hash_output);
    if (ret < 0) {
        printk(KERN_ERR "Hash calculation failed for removal: %d\n", ret);
        kfree(desc);
        crypto_free_shash(tfm);
        return ret;
    }

    crypto_free_shash(tfm);
    kfree(desc);

    // 해시 값으로 키 삭제
    hash_for_each_possible_safe(key_table, key, tmp, hnode, *(u32 *)hash_output) {
        if (memcmp(key->key, hash_output, 32) == 0) { // 해시 값 비교
            hash_del(&key->hnode); // 해시 테이블에서 삭제
            kfree(key->key);       // 메모리 해제
            kfree(key);
            printk(KERN_INFO "Key removed successfully (hash): %s\n", user_key);
            return 0; // 성공적으로 삭제
        }
    }

    printk(KERN_WARNING "Key not found for removal: %s\n", user_key);
    return -ENOENT; // 키를 찾을 수 없음
}


// 키 조회 함수
static void key_list(char *buffer, size_t buffer_size) {
    struct auth_key *key;
    int bkt;
    size_t offset = 0;

    hash_for_each(key_table, bkt, key, hnode) {
        offset += scnprintf(buffer + offset, buffer_size - offset, "%s\n", key->key);
        if (offset >= buffer_size)
            break;
    }
}

// /proc 파일 write 콜백
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char cmd_buffer[256];
    char *cmd, *arg, *temp_buffer;
    ssize_t ret;

    // 입력 크기 확인
    if (count >= sizeof(cmd_buffer)) {
        printk(KERN_WARNING "Input too large: %zu bytes\n", count);
        return -EINVAL;
    }

    // 사용자 입력 데이터를 커널 버퍼로 복사
    if (copy_from_user(cmd_buffer, buffer, count)) {
        printk(KERN_WARNING "Failed to copy data from user space\n");
        return -EFAULT;
    }

    cmd_buffer[count] = '\0'; // 문자열 끝 표시

    // 개행 문자 제거
    if (cmd_buffer[count - 1] == '\n') {
        cmd_buffer[count - 1] = '\0';
    }

    temp_buffer = cmd_buffer;

    // 명령어와 인수 분리
    cmd = strsep(&temp_buffer, " ");
    arg = strsep(&temp_buffer, "\0");

    printk(KERN_INFO "Command: %s, Argument: %s\n", cmd ? cmd : "NULL", arg ? arg : "NULL");

    if (cmd && strcmp(cmd, "register") == 0 && arg) {
        ret = key_register(arg);
        if (ret == -EEXIST) {
            printk(KERN_WARNING "Duplicate key: %s\n", arg);
            return ret; // 중복 키는 -EEXIST 반환
        } else if (ret < 0) {
            printk(KERN_WARNING "Failed to register key: %s\n", arg);
            return ret; // 다른 에러 처리
        }
    } else if (cmd && strcmp(cmd, "remove") == 0 && arg) {
        ret = key_remove(arg);
        if (ret == -ENOENT) {
            printk(KERN_WARNING "Key not found: %s\n", arg);
            return ret; // 키 없음은 -ENOENT 반환
        } else if (ret < 0) {
            printk(KERN_WARNING "Failed to remove key: %s\n", arg);
            return ret; // 다른 에러 처리
        }
    } else {
        printk(KERN_WARNING "Invalid command or argument: cmd=%s, arg=%s\n",
               cmd ? cmd : "NULL", arg ? arg : "NULL");
        return -EINVAL;
    }

    return count; // 성공 시 입력 크기 반환
}

// /proc 파일 read 콜백
static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *pos) {
    static char *output_buffer;
    static size_t output_len;
    static size_t output_offset;
    struct auth_key *key;
    int bkt;
    char hex_output[65]; // SHA-256 결과를 HEX 문자열로 변환 (64바이트 + null)
    size_t offset = 0;

    if (*pos == 0) {
        output_buffer = kmalloc(4096, GFP_KERNEL);
        if (!output_buffer)
            return -ENOMEM;

        hash_for_each(key_table, bkt, key, hnode) {
            bin2hex(hex_output, key->key, 32); // 바이너리 해시를 HEX 문자열로 변환
            hex_output[64] = '\0'; // null-terminated string
            offset += scnprintf(output_buffer + offset, 4096 - offset, "%s\n", hex_output);
            if (offset >= 4096)
                break;
        }
        output_len = offset;
        output_offset = 0;
    }

    if (output_offset >= output_len) {
        kfree(output_buffer);
        return 0;
    }

    count = min(count, output_len - output_offset);
    if (copy_to_user(buffer, output_buffer + output_offset, count)) {
        kfree(output_buffer);
        return -EFAULT;
    }

    output_offset += count;
    *pos += count;
    return count;
}

static const struct proc_ops proc_fops = {
    .proc_write = proc_write,
    .proc_read = proc_read,
};

static int __init key_module_init(void) {
    if (!proc_create(PROC_FILENAME, 0666, NULL, &proc_fops)) {
        printk(KERN_ERR "Failed to create /proc/%s\n", PROC_FILENAME);
        return -ENOMEM;
    }
    printk(KERN_INFO "/proc/%s created\n", PROC_FILENAME);
    return 0;
}

static void __exit key_module_exit(void) {
    remove_proc_entry(PROC_FILENAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROC_FILENAME);
}

module_init(key_module_init);
module_exit(key_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jongchan Hong");
MODULE_DESCRIPTION("Key Management Module for OCPP");


