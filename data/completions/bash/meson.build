# Install commandline completion files
completions_conf = configuration_data()
completions_conf.set('KERNEL_DIRECTORY', with_kernel_dir)
completions_conf.set('KERNEL_NAMESPACE', with_kernel_namespace)

if (get_option('bash_completions'))
   with_bash_completions_dir = get_option('with-bash-completions-dir')
   if with_bash_completions_dir == ''
      with_bash_completions_dir = join_paths(path_datadir, 'bash-completion', 'completions')
   endif
   configure_file(
     input: 'completions/bash/clr-boot-manager.in',
     output: 'completions/bash/clr-boot-manager',
     configuration: completions_conf,
     install_dir: with_bash_completions_dir,
   )
endif
