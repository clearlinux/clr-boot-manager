mandir = join_paths(path_prefix, get_option('mandir'), 'man1')

# Update man page with paths
man_data = configuration_data()
man_data.set('KERNEL_CONF_DIRECTORY', with_kernel_conf_dir)
man_data.set('KERNEL_DIRECTORY', with_kernel_dir)
man_data.set('VENDOR_KERNEL_CONF_DIRECTORY', with_kernel_vendor_conf_dir)
man_data.set('INITRD_DIRECTORY', with_initrd_dir)
man_data.set('USER_INITRD_DIRECTORY', with_user_initrd_dir)
man_1 = configure_file(input : 'clr-boot-manager.1.in',
                       output : 'clr-boot-manager.1',
                       configuration : man_data,
)

install_data(
    man_1,
    install_dir: mandir,
)
