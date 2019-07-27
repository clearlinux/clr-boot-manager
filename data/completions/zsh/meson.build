# Install commandline completion files
completions_conf = configuration_data()
completions_conf.set('KERNEL_DIRECTORY', with_kernel_dir)
completions_conf.set('KERNEL_NAMESPACE', with_kernel_namespace)

if (get_option('zsh_completions'))
   with_zsh_completions_dir = get_option('with-zsh-completions-dir')
   if with_zsh_completions_dir == ''
      with_zsh_completions_dir = join_paths(path_datadir, 'zsh', 'site-functions')
   endif
   configure_file(
     input: 'completions/zsh/_clr-boot-manager.in',
     output: 'completions/zsh/_clr-boot-manager',
     configuration: completions_conf,
     install_dir: with_zsh_completions_dir,
   )
endif
