# Write systemd unit
data_conf = configuration_data()
data_conf.set('BINDIR', path_bindir)

configure_file(
    input: 'clr-boot-manager-booted.service.in',
    output: 'clr-boot-manager-booted.service',
    configuration: data_conf,
    install_dir: with_systemd_system_unit_dir,
)
