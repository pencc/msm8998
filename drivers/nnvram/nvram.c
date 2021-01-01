#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include<linux/slab.h>

#define STRINGLEN 1024
#define BASE_DIR_NAME     "nvram"
 
char global_buffer[STRINGLEN];
 
struct proc_dir_entry *base = NULL, *proc_nnvram_file = NULL;
 
ssize_t proc_read_nvram(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
        int len, err;
        if(*ppos > 0)
                return 0;
        // for test
        len = strlen(global_buffer);
        err = copy_to_user(buf, global_buffer, len);
        if (err)
                printk("fail to read nvram\n");
        *ppos += len;
        return len;
}

int  CallUserApp(char * argv[])
{
        int ret;
        char *envp[3];

    /*  minimal command environment taken from cpu_run_sbin_hotplug */
        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[2] = NULL;

        if (!argv || !argv[0])
        {
                printk( "%s argument is incorrect\n", __func__);
                return -1;
        }
        ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
   
        if (ret < 0) {
                printk("running nvram helper \"%s \" failed %d\n", argv[0], ret);
        }
        return ret;
}

// param example: ("gb_", "global")
static void parse_conf(const char *key_head, const char *key)
{
	const char *conf_file = "/system/etc/andd.conf";
	const int conf_size = 8192;  // max conf file content size 8KB
	struct file *wconf = NULL;
	char *conf_wireless_mac = NULL;
	char *buf = NULL, *kstart = NULL, *vstart = NULL, *end  = NULL;
	loff_t pos = 0;
	int ret;
	mm_segment_t fs;

        if(NULL == key_head || NULL == key
                || 0 == strlen(key_head) || 0 == strlen(key))
                return;

	wconf = filp_open(conf_file, O_RDONLY, 0);
	if (IS_ERR(wconf)) {
		printk("nvram: fail to open andd conf file\n");
		goto err1;
	} else {
		buf = (char*)kmalloc(conf_size * sizeof(char), GFP_KERNEL);
		if(!buf) {
			printk("nvram: fail to malloc buf\n");
			filp_close(wconf, NULL);
			goto err1;
		}

		buf = memset(buf, '\0', conf_size * sizeof(char));

		fs = get_fs();
		set_fs(KERNEL_DS);

		ret = vfs_read(wconf, buf, conf_size-1, &pos);
		if(ret < 0) {
			printk("nvram: fail to read from conf file\n");
			filp_close(wconf, NULL);
			goto err2;
		}

		set_fs(fs);
		filp_close(wconf, NULL);

                kstart = buf;
                while(kstart - buf < ret) {
                        kstart = strstr(kstart, key_head);
                        if(NULL == kstart)
                                break;
                        else if (kstart != buf && '\n' != *(kstart - 1)) { // not in line begin point
                                kstart++;
                                continue;
                        }
                        kstart = kstart + strlen(key_head);
                        vstart = strstr(kstart, "=") + 1;
                        *(vstart-1) = '\0';

                        end = strstr(vstart, "\n");
                        if(NULL == end) { // in end line
                                end = strstr(vstart, "\0");
                        }

                        if(NULL != end) {
                                *end = '\0';
                                char * argv[] = {"/bin/cmd", "settings", "put",
                                key, kstart, vstart, NULL};
                                printk("nvram debug: %s:%s\n", kstart, vstart);
                                CallUserApp(argv);
                        }

                        kstart = end + 1;
                }

		kfree(buf);
		return;
	}

err2:
	kfree(buf);
err1:
	return;
}
 
ssize_t proc_write_nvram(struct file *file, const char __user *buf, size_t count, loff_t *offs) {
        int len = 0;
        if (count >= STRINGLEN)
                len = STRINGLEN - 1;
        else
                len = count;

        copy_from_user(global_buffer, buf, len);
        global_buffer[len] = '\0';

        // call settings
        // char * argv[] = {"/bin/cmd", "settings", "put", "global", "device_name", "TEST P13", NULL};
        // CallUserApp(argv);
        parse_conf("gb_", "global");
        parse_conf("sc_", "secure");

        return len;
}

static const struct file_operations nvram_ops = {
    .owner = THIS_MODULE,
    .write = proc_write_nvram,
    .read = proc_read_nvram,
};

static int __init proc_nvram_init(void) {
        base = proc_mkdir(BASE_DIR_NAME, NULL);
        if(base == NULL){
                printk("%s proc create %s failed\n", __func__, BASE_DIR_NAME);
                return -EINVAL;
        }
        proc_nnvram_file = proc_create("controller", 0777, base, &nvram_ops);
        if(proc_nnvram_file == NULL){
                printk("%s proc create %s failed\n", __func__, BASE_DIR_NAME);
                return -EINVAL;
        }
        strcpy(global_buffer, "wait for init...\n");
        return 0;
}
 
static void __exit proc_nvram_exit(void) {
        proc_remove(proc_nnvram_file);
        proc_remove(base);
}

static int nvram_init(void){
        proc_nvram_init();

        return 0;
}

static void nvram_exit(void){
        proc_nvram_exit();
}

MODULE_LICENSE("GPL");

module_init(nvram_init);
module_exit(nvram_exit);
