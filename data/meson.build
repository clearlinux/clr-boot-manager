# Write systemd unit
data_conf = configuration_data()
data_conf.set('BINDIR', path_bindir)
data_conf.set('BOOTDIR', with_boot_dir)

configure_file(
    input: 'clr-boot-manager-booted.service.in',
    output: 'clr-boot-manager-booted.service',
    configuration: data_conf,
    install_dir: with_systemd_system_unit_dir,
)

configure_file(
    input: 'clr-boot-manager-mount-boot.service.in',
    output: 'clr-boot-manager-mount-boot.service',
    configuration: data_conf,
    install_dir: with_systemd_system_unit_dir,
)
