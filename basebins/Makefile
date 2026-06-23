all:
	$(MAKE) -C jbutil all
	$(MAKE) -C launchd_hook all
	$(MAKE) -C base_hook all
	$(MAKE) -C libjailbreak all

clean:
	$(MAKE) -C jbutil clean
	$(MAKE) -C launchd_hook clean
	$(MAKE) -C base_hook clean
	$(MAKE) -C libjailbreak clean

	@rm -rf ./staging
	@rm -rf ./basebins.tar

package: clean all
	@mkdir -p ./staging
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/amethyst
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/usr/lib

	@cp -a ./jbutil/jbutil ./staging/amethyst/jbutil
	@cp -a ./launchd_hook/launchd_hook.dylib ./staging/amethyst/launchd_hook.dylib
	@cp -a ./base_hook/base_hook.dylib ./staging/usr/lib/base_hook.dylib
	@cp -a ./libjailbreak/libjailbreak.dylib ./staging/usr/lib/libjailbreak.dylib

	@chmod 0755 ./staging/amethyst/jbutil
	@chmod 0755 ./staging/amethyst/launchd_hook.dylib
	@chmod 0755 ./staging/usr/lib/base_hook.dylib
	@chmod 0755 ./staging/usr/lib/libjailbreak.dylib

	@find ./staging -name '.DS_Store' -type f -delete
	cd ./staging && COPYFILE_DISABLE=1 tar --numeric-owner -c --no-xattrs -f ../basebins.tar ./*
