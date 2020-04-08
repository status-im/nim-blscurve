# TODO cycle counting on ARM
#
# - see writeup: http://zhiyisun.github.io/2016/03/02/How-to-Use-Performance-Monitor-Unit-(PMU)-of-64-bit-ARMv8-A-in-Linux.html
#
# Otherwise Google or FFTW approach might work but might require perf_counter privilege (`kernel.perf_event_paranoid=0` ?)
# - https://github.com/google/benchmark/blob/0ab2c290/src/cycleclock.h#L127-L151
# - https://github.com/FFTW/fftw3/blob/ef15637f/kernel/cycle.h#L518-L564
# - https://github.com/vesperix/FFTW-for-ARMv7/blob/22ec5c0b/kernel/cycle.h#L404-L457
