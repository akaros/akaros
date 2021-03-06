Getting Started with Akaros
==========================
Barret Rhoden

Last thorough update: **2013-02-07**

Contents
-----------
+ Overview
+ Need Help?
+ From Download to Hello World
  - Cross compiler (and glibc)
  - Kernel
  - Userspace
  - Building and Loading a Virtual Machine Image
  - Running Qemu
  - Running on Hardware
  - Hello World
  - Other Dev Workflow Stuff
+ RISCV
+ Other Developer's Stuff


1. Overview
---------------------
In this document, I outline what steps I go through to set up my development
environment.  Some devs use other setups, and they can put sections farther
down in this document describing their steps.

Due to the nature of different workflows and different Linux distros, you'll
need to do some configuration of your environment.  Things won't magically work
out of the box.


2. Need Help?
---------------------
First off, if you get stuck, email someone.  You can join our mailing list by
sending an email to
[akaros+subscribe@googlegroups.com](mailto:akaros%2Bsubscribe@googlegroups.com)
or visit the [group](http://groups.google.com/group/akaros).  Once you've
joined, send your messages to <mailto:akaros@googlegroups.com>.

Alternatively, you can poke your head in #akaros on `irc.freenode.net`.  I'm
usually idling in there (alone), and if I'm at my computer, I'll respond.


3. From Download to Hello World
----------------------------
I'll describe how to get x86 working.  RISCV is similar.

To start off, make sure AKAROS_ROOT and AKAROS_TOOLCHAINS are set in your
environment.  AKAROS_ROOT is the Akaros repo directory.  AKAROS_TOOLCHAINS is a
directory of your choosing where the toolchain will be installed (more on that
in Section 3.1 below).

I also suggest running `scripts/one-time-setup.sh`, once per `git clone`.  This
performs various checks and other setup.  Check it out for details.

The first step is to configure the kernel.  Targets like `config`,
`menuconfig`, and some of the other KBuild targets work.  Defconfig gives you a
default configuration.  For example, to config for 64-bit x86:

`$ make ARCH=x86 defconfig`

Alternatively, you can run menuconfig to customize what settings you want:

`$ make ARCH=x86 menuconfig`

For x86, you can choose between 32 and 64 bit when you `make menuconfig`.  This
selection must match your cross compiler `make` command.  The default is 64
bit.

There are a lot of other settings when you `make config`, and you should browse
through to decide what you want to enable/disable.

Most everyone wants KFS turned on (Filesystems --> KFS filesystem).  This is
the in-memory filesystem that the kernel uses.  The kernel build scripts will
look at the "KFS/Initramfs paths" string and take any of those directories and
add them to a CPIO archive that will eventually become the root filesystem when
Akaros runs. These settings are set by default when you do a `make defconfig`.

There are also settings for `ext2`.  If you turn on `ext2` support, you need to
point to an `img` file that has been formatted with `ext2` and has files in it.
If you aren't messing with filesystems at all, feel free to ignore this.  It's
an in-memory filesystem, like KFS (linked to the end of the kernel), so you
won't gain much by using it for now.

### 3.1 Cross compiler (and glibc)
The second step is to build the cross compiler, which lives in
`tools/compilers/gcc-glibc`

`$ cd tools/compilers/gcc-glibc`

You should already have set your `AKAROS_TOOLCHAINS` to some place where you
want the cross compiler installed.  I have a directory named `akaros-gcc-glibc`
for this. My bash environment variables are -

```bash
export AKAROS_ROOT=/home/brho/classes/akaros/akaros-kernel
export AKAROS_TOOLCHAINS=/home/brho/classes/akaros/akaros-gcc-glibc
```

You can also set up `MAKE_JOBS`, so you don't over or under load your system
when building.  I have a 2 core laptop, so I use `MAKE_JOBS := 3`

At this point, you can build (for example):

`$ make x86_64`

This might take a while (10-20 minutes for me on a 2007 era laptop).

Next you will need to add `bin` directories to your `PATH` where the cross
compiler was installed.  This will vary based on the architecture you built the
toolchain for.  Refer below for updating your PATH -

* For riscv, add `$AKAROS_TOOLCHAINS/riscv-ucb-akaros-gcc/bin` to your PATH.
* For x86_64, add `$AKAROS_TOOLCHAINS/x86_64-ucb-akaros-gcc/bin` to your PATH.
* For x86_64 native, add `$AKAROS_TOOLCHAINS/x86_64-ucb-akaros-gcc-native/bin`
to your PATH.

Just to double check everything installed correctly, you should be able to run
`x86_64-ucb-akaros-gcc` from your shell.

Now, you have a cross compiler ready, and you can start to build Akaros.

### 3.2 Kernel
`cd` back into the repo root.

Like the cross compiler, the kernel has its own `Makelocal`.

`$ cp Makelocal.template Makelocal`

This file is used to set up custom make targets that are not part of the
default `Makefile`, but fit nicely into your personal workflow. This file is
not under version control and can be made to contain just about anything.

Now you're ready to build the kernel:

`$ make`

So the kernel built, but you can't do much with it, and you probably have no
programs.

Notice that we didn't have to set the `ARCH` variable this time.  The make
system knows what architecture we are set up for and will always build for that
architecture until a new `ARCH` is selected (i.e. via `make ARCH=xxx defconfig`
etc.)

### 3.3 Userspace
First, you'll need to build a few common applications and libraries:

`$ make apps-install`

Then you can build the tests and small utility programs:

`$ make tests`

You now have programs and libraries, and need to put them in KFS.  To do this,
we provide a `fill-kfs` make target.

`$ make fill-kfs`

The `fill-kfs` target copies your cross compiler's shared libraries and all
test binaries into the first "KFS/Initramfs path" you set during configuration
(or `kern/kfs/lib` if you just kept the default).

Now that you've changed the contents of KFS's source, remake the kernel.  You
should see something like the following before the kernel links.  If you don't
see this, then you probably didn't actually fill KFS properly.

```
	Building initramfs:
	Adding kern/kfs to initramfs...
```

### 3.4 Building and Loading a Virtual Machine Image
At this point, you probably have a runnable kernel with programs in KFS.  It
should be sitting at `obj/kern/akaros-kernel`.  When running in a VM, you can
either run the kernel directly from `qemu`, or put it in a virtual machine
image file.

If you don't want to bother with the image, skip this section.  I tend to run
my images off an image file, since `qemu` acts more like hardware (as far as
multiboot goes).  The downside is the boot up is slower, especially if you have
a large kernel (>100MB).  It also takes some effort to set up the VM image.

If you are still reading, you'll need an image file that looks like a hard disk
to boot `qemu` off of.  I put one similar to mine at:
<http://akaros.cs.berkeley.edu/files/hdd268mb.img>

It's around 268MB (256MiB, or whatever).  If you want to make your own, check out
[Documentation/howtos/make-bootable-grub-hdd.txt](Documentation/howtos/make-bootable-grub-hdd.txt).
That's actually the original document I made back when I first figured it out
back in 2009, which was updated again in 2013.  In between, I wrote it up
online at
<http://www.omninerd.com/articles/Installing_GRUB_on_a_Hard_Disk_Image_File>,
which has some other tidbits in the comments.  Both methods still use `grub1`.

Anyway, I put that img in `AKAROS-ROOT/mnt/`, and make a folder next to it:
`AKAROS-ROOT/mnt/hdd`.  `mnt/hdd` is the mount point where I mount `hdd.img`
(Note I don't call it `hdd64mb.img` on my dev machine).

Personally, I always have `hdd.img` mounted.  Some of the other devs have make
targets that mount and umount it.  Whenever I reboot my development machine, I
run a script (as root) that mounts the image file and sets up a few things for
networking.  I put a script I use for this in `scripts/kvm-up.sh`.  You'll
likely want to copy it to the directory **above** the akaros root directory and
edit it accordingly. Feel free to comment out the networking stuff.  That's for
using networking in `qemu`.

Now that your image file is mounted at `mnt/hdd`, you'll want to copy your
freshly built kernel to the root of the image.  I have a make target in my
makelocal for this, so that whenever I do a `make kvm`, it builds the kernel
and copies it to my `hdd.img`.

I added edited versions of my KVM (and USB) make targets to the
`Makelocal.template`.  Uncomment the KVM one (at least).

Incidentally, I also have the following in my `Makelocal`, so that `make` (and
`make all`) also make kvm:

`all: kvm`

Now, `make kvm`.  You should be able to see the new kernel in `mnt/hdd/` (do an
`ls -l` and check the timestamp).

### 3.5 Running Qemu
Here is the command I use to run `qemu`/`kvm`.  It's evolved over the years,
and it will vary based on your linux distribution.  Don't run it just yet:

```
$ qemu-system-x86_64 -s -enable-kvm -cpu kvm64 -smp 8 -m 4096 -nographic -monitor /dev/pts/3 -net nic,model=e1000 -net user,hostfwd=tcp::5555-:22 -net dump,file=/tmp/vm.pcap -drive file=mnt/hdd.img,index=0,media=disk,format=raw
```

If you skipped making a virtual machine image or want to run the kernel
directly without emulating a disk, replace the "`-drive`" parameter (all the way
to `format=raw`) with "`-kernel obj/kern/akaros-kernel`".

The `-monitor` is the qemu monitor, which is a CLI for qemu.  Pick a
tab/terminal/pty in Linux that you will only use for qemu monitoring, and enter
'`tty`'.  Whatever it tells you, put in place of `/dev/pts/3`.  I've been using
the same tab for about 4 years now.  In that tab, enter '`sleep 999999999`'.
Qemu will still access it, but you won't have to worry about bash trying to
handle your inputs.

`-nographic` allows qemu to work in the terminal you run qemu from, instead of
spawning off a fake cpu crt/monitor.

The command as written uses qemu's user networking.  It's emulated and a little
slow.  The example I have alo forwards port `5555` on the host to port `22` on
the guest.  Customize it according to your needs.

Another option for networking is to set up a tun/tap device.  I use this on
some machines, and the kvm-up script has some commands to set it up.  It's
tricky, and may vary for your distribution.  If you do use the tun/tap
networking, replace the "`-net user`" section with:

`-net tap,ifname=tap0,script=no`

The "`-net dump`" option saves a pcap trace of the network traffic.  This is
very useful for debugging, but probably not needed for most people.

Feel free to pick different values for the number of cpus and RAM (8 and 4096
in the example).

Once you finally run it, you can stop the VM by entering '`q`' to the qemu
monitor (or just killing the process)..  Other help commands from the monitor
include '`info cpus`', '`info registers`', '`x`', and '`help`'.

In more recent versions of qemu, `CTRL-C` will not get sent to the guest;
instead it will kill the VM.  If this gets annoying, you can remap "interrupt"
to something other than `CTRL-C` in the terminal where you run qemu:

`$ stty intr ^]`

To change it back:

`$ stty intr ^c`


### 3.6 Running on Hardware
I have a few bootable USB sticks with grub set up to run Akaros.  The make usb
target (example in `Makelocal.template`) will copy freshly made kernels to your
USB device.  You'll need to adjust those paths according to your distro.  My
usb sticks are usually `/dev/sdc`, for instance (some odd USB device in the
last couple of years has taken over `/dev/sdb`.  Probably something to do with
`udev` changing over the years).

Anyway, you'll need to mess around a bit to get that working.  Or I can `dd` one
for you (I have 4GB disks in my office that I use).  If you make your own, the
critical part is getting grub to pick the right device (from what I remember),
and its fairly similar to installing grub on any old hard drive (since it's
just a bloc device).  Much easier than a hard disk image file.


### 3.7 Hello World
So now you can run the kernel.  It's time to edit a program (or make your own).
In this, I'll go through my workflow for making changes.

```
$ vi tests/hello.c
(edit, save)

$ make tests
(new version in obj/tests/hello)

$ make fill-kfs
(updates kfs)

$ make
(rebuilds kernel with the new KFS)

$ qemu...

(following commands are in Akaros)
Shift-G (to get to the kernel monitor)

ROS(Core 0)> bb (to run busybox)

/ $ hello
(Should print your message)
```

### 3.8 Other Dev Workflow Stuff
One thing to note is that while we use dynamic linking for `libc`, `parlib`
libraries are statically linked with applications.  In fact, nowadays **all**
Akaros programs need to be linked againt `parlib` (used to be that single-core
processes (SCPs) didn't need it).

The makefiles won't notice if you change a file in `parlib` and then remake a
binary.  So if you edit `user/parlib/uthread.c` for example,
`tests/pthread_test` won't get rebuilt.  Here's what I do:

```
$ vi user/parlib/uthread.c (make awesome change)

$ touch tests/pthread_test.c ; make tests
```

This will force the rebuild of `pthread_test`.  Older, untouched binaries (e.g.
`block_test`), won't get rebuilt.  I actually want this in some cases
(different versions of `parlib` when I'm running certain tests).  Anyway, just
pay attention to what you're building.  There's not much output in the console,
so you should be able to see what's going on all the time.  (unlike when
building `glibc`...).

Oh, and don't forget to:

`$ make fill-kfs`

to make sure you run the new `pthread_test`.

Additionally, when switching between 32 and 64 bit x86, `make objclean` before
filling KFS.  This is the easiest way to make sure you get the appropriate
libraries loaded in KFS.

Early on as a dev, there are lots of times where you accidentally don't run the
right program (or kernel) and won't understand why your change isn't happening.
A few `printk("WTF\n")`'s later, you realize you didn't have the `hdd.img`
mounted, or you didn't fill KFS, or you didn't relink your binaries, or you
forgot to save all files in `vi` (and not just the current buffer).  But after
doing a couple `hello worlds`, you're set.

Alternatively, you could have a make target to run qemu, which also touches all
binaries (or otherwise enforces a rebuild), auto-fills KFS, remakes the kernel,
and mounts/copies/unmounts your `hdd.img`.
Personally, I like to keep track of what is going on under the hood, esp if I
want to do something a little differently (like with testing `ext2`, having
different versions of `parlib` with some binaries, or being picky about my
mount/umounts).


4. RISCV
---------------------
**TODO**.

For now, you need a 64 bit distro to build the RISCV stuff, so I don't do it
very often.  I'll eventually sync up with Andrew and we'll get this part sorted
out.


5. Other Developer's Stuff
--------------------------
Nothing for now...
