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
	{ 0x64cfa846, "remove_proc_entry" },
	{ 0x50061c0d, "proc_create" },
	{ 0x96848186, "scnprintf" },
	{ 0xd45cc6ca, "bin2hex" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x9ba84108, "kmem_cache_alloc_trace" },
	{ 0xb4c43206, "kmalloc_caches" },
	{ 0x449ad0a7, "memcmp" },
	{ 0x6677e547, "crypto_shash_digest" },
	{ 0xc37a2a2b, "crypto_destroy_tfm" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x37a0cba, "kfree" },
	{ 0x228de854, "key_table" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xe5d97e49, "crypto_alloc_shash" },
	{ 0x754d539c, "strlen" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x92997ed8, "_printk" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x85df9b6c, "strsep" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "C75350C595CC44427D1BA26");
