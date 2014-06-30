#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x19a7f3b8, "module_layout" },
	{ 0x2a1830d1, "kmalloc_caches" },
	{ 0xc4f00020, "sock_release" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0x33a31e5f, "nf_register_hook" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xe40ac24a, "netlink_kernel_create" },
	{ 0xb72397d5, "printk" },
	{ 0xb4390f9a, "mcount" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x148b660f, "netlink_unicast" },
	{ 0xb8c3eaa4, "init_net" },
	{ 0x602e7302, "kmem_cache_alloc" },
	{ 0xa52709da, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x599649d7, "kfree_skb" },
	{ 0x8bc40bf5, "netlink_ack" },
	{ 0x3b2bcfed, "nf_unregister_hook" },
	{ 0x93156f, "skb_put" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "1A11373411456FD87839329");
