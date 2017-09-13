Userspace MIPS emulator.  Mostly a toy, but makes easy to interpret instruction traces, like this (scroll to the right, there's a stack trace there):


```
   120776d24:   00000000        sll     zero,zero,0                                                     #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   12077a0e0:   67bdfff0        daddiu  sp,sp,-16     # sp := 0x00007fffffffa308 (140737488331528)      #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a0e4:   ffbc0000        sd      gp,0(sp)                                                        #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a0e8:   3c1c0026        lui     gp,38         # gp := 0x0000000000260000 (2490368)              #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a0ec:   0399e02d        daddu   gp,gp,t9      # gp := 0x00000001209da0e0 (4842168544)           #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a0f0:   679c68f0        daddiu  gp,gp,26864   # gp := 0x00000001209e09d0 (4842195408)           #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a0f4:   10c0000f        beq     a2,zero,15    # not taken                                       #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a0f8:   0000102d        daddu   v0,zero,zero  # v0 := 000000000000000000 (0)                    #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a0fc:   00000000        sll     zero,zero,0                                                     #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a100:   80830000        lb      v1,0(a0)      # v1 := 0x0000000000000050 (80)                   #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a104:   80a20000        lb      v0,0(a1)      # v0 := 0x000000000000004d (77)                   #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a108:   10430005        beq     v0,v1,5       # not taken                                       #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a10c:   64a50001        daddiu  a1,a1,1       # a1 := 0x000000012094ffd9 ("ALLOC_CONF")         #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a110:   90830000        lbu     v1,0(a0)      # v1 := 0x0000000000000050 (80)                   #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a114:   90a2ffff        lbu     v0,-1(a1)     # v0 := 0x000000000000004d (77)                   #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a118:   10000006        beq     zero,zero,6   # taken                                           #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a11c:   00621023        subu    v0,v1,v0      # v0 := 0x0000000000000003 (3)                    #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a134:   dfbc0000        ld      gp,0(sp)      # gp := 0x0000000120a03868 (4842338408)           #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a138:   03e00008        jr      ra                                                              #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   12077a13c:   67bd0010        daddiu  sp,sp,16      # sp := 0x00007fffffffa318 (140737488331544)      #   strncmp getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _in
   120776d28:   54400045        bnel    v0,zero,69    # taken                                           #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776d2c:   de320008        ld      s2,8(s1)      # s2 := 0x00007fffffffef05 ("SHELL=/bin/bash")    #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776e40:   1640ffb3        bne     s2,zero,-77   # taken                                           #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776e44:   66310008        daddiu  s1,s1,8       # s1 := 0x00007fffffffa9e8 (140737488333288)      #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776d10:   0240202d        daddu   a0,s2,zero    # a0 := 0x00007fffffffef05 ("SHELL=/bin/bash")    #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776d14:   0200282d        daddu   a1,s0,zero    # a1 := 0x000000012094ffd8 ("MALLOC_CONF")        #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776d18:   0260302d        daddu   a2,s3,zero    # a2 := 0x000000000000000b (11)                   #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776d1c:   df99ff48        ld      t9,-184(gp)   # t9 := 0x000000012077a0e0 ("g")                  #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
   120776d20:   0320f809        jalr    ra,t9         # ra := 0x0000000120776d28 ("T@")                 #     getenv malloc_init_hard_a0_locked malloc_init jemalloc_constructor __do_global_ctors_aux _init __s
```

