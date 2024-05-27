# SPDX-License-Identifier: CC0-1.0

# Cache system paths
libcamera_datadir = get_option('datadir') / 'libcamera'
libcamera_libdir = get_option('libdir') / 'libcamera'
libcamera_libexecdir = get_option('libexecdir') / 'libcamera'
libcamera_sysconfdir = get_option('sysconfdir') / 'libcamera'

config_h.set('LIBCAMERA_DATA_DIR', '"' + get_option('prefix') / libcamera_datadir + '"')
config_h.set('LIBCAMERA_SYSCONF_DIR', '"' + get_option('prefix') / libcamera_sysconfdir + '"')

summary({
         'LIBCAMERA_DATA_DIR' : config_h.get('LIBCAMERA_DATA_DIR'),
         'LIBCAMERA_SYSCONF_DIR' : config_h.get('LIBCAMERA_SYSCONF_DIR'),
         }, section : 'Paths')

ipa_sign_module = false

# libcamera must be built first as a dependency to the other components.
subdir('libcamera')

subdir('android')
subdir('ipa')

subdir('apps')

subdir('gstreamer')
subdir('py')
subdir('v4l2')
