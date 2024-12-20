#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x6c5c4afa, "module_layout" },
	{ 0x4f10bec6, "nf_unregister_net_hook" },
	{ 0x4b465b2e, "nf_register_net_hook" },
	{ 0xb3a98141, "init_net" },
	{ 0x15fe2c3f, "kfree_skb_reason" },
	{ 0x754d539c, "strlen" },
	{ 0x349cba85, "strchr" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xdbbc063c, "skb_copy_expand" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x9ba84108, "kmem_cache_alloc_trace" },
	{ 0xb4c43206, "kmalloc_caches" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x92997ed8, "_printk" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x228de854, "key_table" },
	{ 0x37a0cba, "kfree" },
	{ 0x6677e547, "crypto_shash_digest" },
	{ 0xa916b694, "strnlen" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xc37a2a2b, "crypto_destroy_tfm" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xe5d97e49, "crypto_alloc_shash" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "0996E19D068ED455442EFE8");
