valgrind                               \
  --tool=memcheck                      \
  --leak-check=full                    \
  --num-callers=50                     \
  --track-origins=yes                  \
  --show-below-main=yes                \
  --read-var-info=yes                  \
  --sim-hints=lax-ioctls               \
  --suppressions=tools/valgrind.supp   \
  --workaround-gcc296-bugs=yes         \
  ./ofss $*


#  --track-fds=yes                      \
#  --show-emwarns=yes                   \
