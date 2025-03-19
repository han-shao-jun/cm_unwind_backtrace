
.\uart.axf:     file format elf32-littlearm


Disassembly of section ER_IROM1:

08000000 <__Vectors>:
 8000000:	90 06 00 20 09 03 00 08 0d 57 00 08 75 56 00 08     ... .....W..uV..
 8000010:	09 57 00 08 4d 0e 00 08 3d 5f 00 08 00 00 00 00     .W..M...=_......
	...
 800002c:	41 57 00 08 7d 0e 00 08 00 00 00 00 17 57 00 08     AW..}........W..
 800003c:	43 57 00 08 23 03 00 08 23 03 00 08 23 03 00 08     CW..#...#...#...
 800004c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800005c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800006c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800007c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800008c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800009c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 80000ac:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 80000bc:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 80000cc:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 80000dc:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 80000ec:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 80000fc:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800010c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800011c:	23 03 00 08 23 03 00 08 23 03 00 08 23 03 00 08     #...#...#...#...
 800012c:	23 03 00 08                                         #...

08000130 <__main>:
 8000130:	f8df d010 	ldr.w	sp, [pc, #16]	@ 8000144 <__rt_final_cpp>

08000134 <_main_scatterload>:
 8000134:	f000 fe34 	bl	8000da0 <__scatterload>

08000138 <__main_after_scatterload>:
 8000138:	4800      	ldr	r0, [pc, #0]	@ (800013c <__main_after_scatterload+0x4>)
 800013a:	4700      	bx	r0
 800013c:	080064dd 	.word	0x080064dd

08000140 <__rt_lib_shutdown_fini>:
 8000140:	f3af 8000 	nop.w

08000144 <__rt_final_cpp>:
 8000144:	20000690 	.word	0x20000690

08000148 <__ARM_Unwind_VRS_VFPpreserve_low>:
 8000148:	ec80 0b20 	vstmia	r0, {d0-d15}
 800014c:	4770      	bx	lr

0800014e <__ARM_Unwind_VRS_VFPpreserve_high>:
 800014e:	ecc0 0b20 	vstmia	r0, {d16-d31}
 8000152:	4770      	bx	lr

08000154 <__ARM_Unwind_VRS_VFPrestore_low>:
 8000154:	ec90 0b20 	vldmia	r0, {d0-d15}
 8000158:	4770      	bx	lr

0800015a <__ARM_Unwind_VRS_VFPrestore_high>:
 800015a:	ecd0 0b20 	vldmia	r0, {d16-d31}
 800015e:	4770      	bx	lr

08000160 <__ARM_Unwind_VRS_corerestore>:
 8000160:	4685      	mov	sp, r0
 8000162:	980d      	ldr	r0, [sp, #52]	@ 0x34
 8000164:	f8dd e038 	ldr.w	lr, [sp, #56]	@ 0x38
 8000168:	9b0f      	ldr	r3, [sp, #60]	@ 0x3c
 800016a:	f85d 2b04 	ldr.w	r2, [sp], #4
 800016e:	e920 000c 	stmdb	r0!, {r2, r3}
 8000172:	e89d 1ffe 	ldmia.w	sp, {r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, ip}
 8000176:	4685      	mov	sp, r0
 8000178:	bd01      	pop	{r0, pc}

0800017a <_Unwind_RaiseException>:
 800017a:	f84d ed08 	str.w	lr, [sp, #-8]!
 800017e:	f10d 0e08 	add.w	lr, sp, #8
 8000182:	f84d ed04 	str.w	lr, [sp, #-4]!
 8000186:	e92d 1fff 	stmdb	sp!, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, ip}
 800018a:	2100      	movs	r1, #0
 800018c:	b402      	push	{r1}
 800018e:	4669      	mov	r1, sp
 8000190:	b081      	sub	sp, #4
 8000192:	f000 fd58 	bl	8000c46 <__ARM_Unwind_RaiseException>
 8000196:	f8dd e040 	ldr.w	lr, [sp, #64]	@ 0x40
 800019a:	b012      	add	sp, #72	@ 0x48
 800019c:	4770      	bx	lr
	...

080001a0 <__ARM_ETInfo>:
 80001a0:	6b88 0000 7020 0000                         .k.. p..

080001a8 <_Unwind_Resume>:
 80001a8:	f84d ed08 	str.w	lr, [sp, #-8]!
 80001ac:	f10d 0e08 	add.w	lr, sp, #8
 80001b0:	f84d ed04 	str.w	lr, [sp, #-4]!
 80001b4:	e92d 1fff 	stmdb	sp!, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, ip}
 80001b8:	2100      	movs	r1, #0
 80001ba:	b402      	push	{r1}
 80001bc:	4669      	mov	r1, sp
 80001be:	b081      	sub	sp, #4
 80001c0:	f000 bda8 	b.w	8000d14 <__ARM_Unwind_Resume>

080001c4 <_Unwind_Activity>:
 80001c4:	4770      	bx	lr
 80001c6:	bf00      	nop

080001c8 <__asm___6_main_c_test_a____REV16>:
 80001c8:	ba40      	rev16	r0, r0
 80001ca:	4770      	bx	lr

080001cc <__asm___6_gpio_c_62724882____REV16>:
 80001cc:	ba40      	rev16	r0, r0
 80001ce:	4770      	bx	lr

080001d0 <__asm___7_usart_c_aa2567c7____REV16>:
 80001d0:	ba40      	rev16	r0, r0
 80001d2:	4770      	bx	lr

080001d4 <__asm___14_stm32f1xx_it_c_bb8ca80c____REV16>:
 80001d4:	ba40      	rev16	r0, r0
 80001d6:	4770      	bx	lr

080001d8 <__asm___19_stm32f1xx_hal_msp_c_d46e2bee____REV16>:
 80001d8:	ba40      	rev16	r0, r0
 80001da:	4770      	bx	lr

080001dc <__asm___23_stm32f1xx_hal_gpio_ex_c_61b0f410____REV16>:
 80001dc:	ba40      	rev16	r0, r0
 80001de:	4770      	bx	lr

080001e0 <__asm___19_stm32f1xx_hal_tim_c____REV16>:
 80001e0:	ba40      	rev16	r0, r0
 80001e2:	4770      	bx	lr

080001e4 <__asm___22_stm32f1xx_hal_tim_ex_c____REV16>:
 80001e4:	ba40      	rev16	r0, r0
 80001e6:	4770      	bx	lr

080001e8 <__asm___20_stm32f1xx_hal_uart_c_d497114f____REV16>:
 80001e8:	ba40      	rev16	r0, r0
 80001ea:	4770      	bx	lr

080001ec <__asm___15_stm32f1xx_hal_c_3da258af____REV16>:
 80001ec:	ba40      	rev16	r0, r0
 80001ee:	4770      	bx	lr

080001f0 <__asm___19_stm32f1xx_hal_rcc_c_b7071a4b____REV16>:
 80001f0:	ba40      	rev16	r0, r0
 80001f2:	4770      	bx	lr

080001f4 <__asm___22_stm32f1xx_hal_rcc_ex_c_bed13b44____REV16>:
 80001f4:	ba40      	rev16	r0, r0
 80001f6:	4770      	bx	lr

080001f8 <__asm___20_stm32f1xx_hal_gpio_c_ea787061____REV16>:
 80001f8:	ba40      	rev16	r0, r0
 80001fa:	4770      	bx	lr

080001fc <__asm___19_stm32f1xx_hal_dma_c_c25f65ec____REV16>:
 80001fc:	ba40      	rev16	r0, r0
 80001fe:	4770      	bx	lr

08000200 <__asm___22_stm32f1xx_hal_cortex_c_2992dbc0____REV16>:
 8000200:	ba40      	rev16	r0, r0
 8000202:	4770      	bx	lr

08000204 <__asm___19_stm32f1xx_hal_pwr_c_f2cfe8be____REV16>:
 8000204:	ba40      	rev16	r0, r0
 8000206:	4770      	bx	lr

08000208 <__asm___21_stm32f1xx_hal_flash_c_48aa8f3e____REV16>:
 8000208:	ba40      	rev16	r0, r0
 800020a:	4770      	bx	lr

0800020c <__asm___24_stm32f1xx_hal_flash_ex_c_6648b60e____REV16>:
 800020c:	ba40      	rev16	r0, r0
 800020e:	4770      	bx	lr

08000210 <__asm___20_stm32f1xx_hal_exti_c_ad9bfa1e____REV16>:
 8000210:	ba40      	rev16	r0, r0
 8000212:	4770      	bx	lr

08000214 <__asm___18_system_stm32f1xx_c_5d646a67____REV16>:
 8000214:	ba40      	rev16	r0, r0
 8000216:	4770      	bx	lr

08000218 <__asm___6_main_c_test_a____REVSH>:
 8000218:	bac0      	revsh	r0, r0
 800021a:	4770      	bx	lr

0800021c <__asm___6_gpio_c_62724882____REVSH>:
 800021c:	bac0      	revsh	r0, r0
 800021e:	4770      	bx	lr

08000220 <__asm___7_usart_c_aa2567c7____REVSH>:
 8000220:	bac0      	revsh	r0, r0
 8000222:	4770      	bx	lr

08000224 <__asm___14_stm32f1xx_it_c_bb8ca80c____REVSH>:
 8000224:	bac0      	revsh	r0, r0
 8000226:	4770      	bx	lr

08000228 <__asm___19_stm32f1xx_hal_msp_c_d46e2bee____REVSH>:
 8000228:	bac0      	revsh	r0, r0
 800022a:	4770      	bx	lr

0800022c <__asm___23_stm32f1xx_hal_gpio_ex_c_61b0f410____REVSH>:
 800022c:	bac0      	revsh	r0, r0
 800022e:	4770      	bx	lr

08000230 <__asm___19_stm32f1xx_hal_tim_c____REVSH>:
 8000230:	bac0      	revsh	r0, r0
 8000232:	4770      	bx	lr

08000234 <__asm___22_stm32f1xx_hal_tim_ex_c____REVSH>:
 8000234:	bac0      	revsh	r0, r0
 8000236:	4770      	bx	lr

08000238 <__asm___20_stm32f1xx_hal_uart_c_d497114f____REVSH>:
 8000238:	bac0      	revsh	r0, r0
 800023a:	4770      	bx	lr

0800023c <__asm___15_stm32f1xx_hal_c_3da258af____REVSH>:
 800023c:	bac0      	revsh	r0, r0
 800023e:	4770      	bx	lr

08000240 <__asm___19_stm32f1xx_hal_rcc_c_b7071a4b____REVSH>:
 8000240:	bac0      	revsh	r0, r0
 8000242:	4770      	bx	lr

08000244 <__asm___22_stm32f1xx_hal_rcc_ex_c_bed13b44____REVSH>:
 8000244:	bac0      	revsh	r0, r0
 8000246:	4770      	bx	lr

08000248 <__asm___20_stm32f1xx_hal_gpio_c_ea787061____REVSH>:
 8000248:	bac0      	revsh	r0, r0
 800024a:	4770      	bx	lr

0800024c <__asm___19_stm32f1xx_hal_dma_c_c25f65ec____REVSH>:
 800024c:	bac0      	revsh	r0, r0
 800024e:	4770      	bx	lr

08000250 <__asm___22_stm32f1xx_hal_cortex_c_2992dbc0____REVSH>:
 8000250:	bac0      	revsh	r0, r0
 8000252:	4770      	bx	lr

08000254 <__asm___19_stm32f1xx_hal_pwr_c_f2cfe8be____REVSH>:
 8000254:	bac0      	revsh	r0, r0
 8000256:	4770      	bx	lr

08000258 <__asm___21_stm32f1xx_hal_flash_c_48aa8f3e____REVSH>:
 8000258:	bac0      	revsh	r0, r0
 800025a:	4770      	bx	lr

0800025c <__asm___24_stm32f1xx_hal_flash_ex_c_6648b60e____REVSH>:
 800025c:	bac0      	revsh	r0, r0
 800025e:	4770      	bx	lr

08000260 <__asm___20_stm32f1xx_hal_exti_c_ad9bfa1e____REVSH>:
 8000260:	bac0      	revsh	r0, r0
 8000262:	4770      	bx	lr

08000264 <__asm___18_system_stm32f1xx_c_5d646a67____REVSH>:
 8000264:	bac0      	revsh	r0, r0
 8000266:	4770      	bx	lr

08000268 <__asm___6_main_c_test_a____RRX>:
 8000268:	ea4f 0030 	mov.w	r0, r0, rrx
 800026c:	4770      	bx	lr
	...

08000270 <__asm___6_gpio_c_62724882____RRX>:
 8000270:	ea4f 0030 	mov.w	r0, r0, rrx
 8000274:	4770      	bx	lr
	...

08000278 <__asm___7_usart_c_aa2567c7____RRX>:
 8000278:	ea4f 0030 	mov.w	r0, r0, rrx
 800027c:	4770      	bx	lr
	...

08000280 <__asm___14_stm32f1xx_it_c_bb8ca80c____RRX>:
 8000280:	ea4f 0030 	mov.w	r0, r0, rrx
 8000284:	4770      	bx	lr
	...

08000288 <__asm___19_stm32f1xx_hal_msp_c_d46e2bee____RRX>:
 8000288:	ea4f 0030 	mov.w	r0, r0, rrx
 800028c:	4770      	bx	lr
	...

08000290 <__asm___23_stm32f1xx_hal_gpio_ex_c_61b0f410____RRX>:
 8000290:	ea4f 0030 	mov.w	r0, r0, rrx
 8000294:	4770      	bx	lr
	...

08000298 <__asm___19_stm32f1xx_hal_tim_c____RRX>:
 8000298:	ea4f 0030 	mov.w	r0, r0, rrx
 800029c:	4770      	bx	lr
	...

080002a0 <__asm___22_stm32f1xx_hal_tim_ex_c____RRX>:
 80002a0:	ea4f 0030 	mov.w	r0, r0, rrx
 80002a4:	4770      	bx	lr
	...

080002a8 <__asm___20_stm32f1xx_hal_uart_c_d497114f____RRX>:
 80002a8:	ea4f 0030 	mov.w	r0, r0, rrx
 80002ac:	4770      	bx	lr
	...

080002b0 <__asm___15_stm32f1xx_hal_c_3da258af____RRX>:
 80002b0:	ea4f 0030 	mov.w	r0, r0, rrx
 80002b4:	4770      	bx	lr
	...

080002b8 <__asm___19_stm32f1xx_hal_rcc_c_b7071a4b____RRX>:
 80002b8:	ea4f 0030 	mov.w	r0, r0, rrx
 80002bc:	4770      	bx	lr
	...

080002c0 <__asm___22_stm32f1xx_hal_rcc_ex_c_bed13b44____RRX>:
 80002c0:	ea4f 0030 	mov.w	r0, r0, rrx
 80002c4:	4770      	bx	lr
	...

080002c8 <__asm___20_stm32f1xx_hal_gpio_c_ea787061____RRX>:
 80002c8:	ea4f 0030 	mov.w	r0, r0, rrx
 80002cc:	4770      	bx	lr
	...

080002d0 <__asm___19_stm32f1xx_hal_dma_c_c25f65ec____RRX>:
 80002d0:	ea4f 0030 	mov.w	r0, r0, rrx
 80002d4:	4770      	bx	lr
	...

080002d8 <__asm___22_stm32f1xx_hal_cortex_c_2992dbc0____RRX>:
 80002d8:	ea4f 0030 	mov.w	r0, r0, rrx
 80002dc:	4770      	bx	lr
	...

080002e0 <__asm___19_stm32f1xx_hal_pwr_c_f2cfe8be____RRX>:
 80002e0:	ea4f 0030 	mov.w	r0, r0, rrx
 80002e4:	4770      	bx	lr
	...

080002e8 <__asm___21_stm32f1xx_hal_flash_c_48aa8f3e____RRX>:
 80002e8:	ea4f 0030 	mov.w	r0, r0, rrx
 80002ec:	4770      	bx	lr
	...

080002f0 <__asm___24_stm32f1xx_hal_flash_ex_c_6648b60e____RRX>:
 80002f0:	ea4f 0030 	mov.w	r0, r0, rrx
 80002f4:	4770      	bx	lr
	...

080002f8 <__asm___20_stm32f1xx_hal_exti_c_ad9bfa1e____RRX>:
 80002f8:	ea4f 0030 	mov.w	r0, r0, rrx
 80002fc:	4770      	bx	lr
	...

08000300 <__asm___18_system_stm32f1xx_c_5d646a67____RRX>:
 8000300:	ea4f 0030 	mov.w	r0, r0, rrx
 8000304:	4770      	bx	lr
	...

08000308 <Reset_Handler>:
 8000308:	4806      	ldr	r0, [pc, #24]	@ (8000324 <ADC1_2_IRQHandler+0x2>)
 800030a:	4780      	blx	r0
 800030c:	4806      	ldr	r0, [pc, #24]	@ (8000328 <ADC1_2_IRQHandler+0x6>)
 800030e:	4700      	bx	r0
 8000310:	e7fe      	b.n	8000310 <Reset_Handler+0x8>
 8000312:	e7fe      	b.n	8000312 <Reset_Handler+0xa>
 8000314:	e7fe      	b.n	8000314 <Reset_Handler+0xc>
 8000316:	e7fe      	b.n	8000316 <Reset_Handler+0xe>
 8000318:	e7fe      	b.n	8000318 <Reset_Handler+0x10>
 800031a:	e7fe      	b.n	800031a <Reset_Handler+0x12>
 800031c:	e7fe      	b.n	800031c <Reset_Handler+0x14>
 800031e:	e7fe      	b.n	800031e <Reset_Handler+0x16>
 8000320:	e7fe      	b.n	8000320 <Reset_Handler+0x18>

08000322 <ADC1_2_IRQHandler>:
 8000322:	e7fe      	b.n	8000322 <ADC1_2_IRQHandler>
 8000324:	08005855 	.word	0x08005855
 8000328:	08000131 	.word	0x08000131

0800032c <__aeabi_unwind_cpp_pr1>:
 800032c:	2301      	movs	r3, #1
 800032e:	f000 b83d 	b.w	80003ac <__ARM_unwind_cpp_prcommon>

08000332 <__aeabi_unwind_cpp_pr0>:
 8000332:	2300      	movs	r3, #0
 8000334:	f000 b83a 	b.w	80003ac <__ARM_unwind_cpp_prcommon>

08000338 <__aeabi_llsr>:
 8000338:	2a20      	cmp	r2, #32
 800033a:	db04      	blt.n	8000346 <__aeabi_llsr+0xe>
 800033c:	3a20      	subs	r2, #32
 800033e:	fa21 f002 	lsr.w	r0, r1, r2
 8000342:	2100      	movs	r1, #0
 8000344:	4770      	bx	lr
 8000346:	fa21 f302 	lsr.w	r3, r1, r2
 800034a:	40d0      	lsrs	r0, r2
 800034c:	f1c2 0220 	rsb	r2, r2, #32
 8000350:	4091      	lsls	r1, r2
 8000352:	4308      	orrs	r0, r1
 8000354:	4619      	mov	r1, r3
 8000356:	4770      	bx	lr

08000358 <__aeabi_memset>:
 8000358:	b2d2      	uxtb	r2, r2
 800035a:	e001      	b.n	8000360 <__aeabi_memset+0x8>
 800035c:	f800 2b01 	strb.w	r2, [r0], #1
 8000360:	1e49      	subs	r1, r1, #1
 8000362:	d2fb      	bcs.n	800035c <__aeabi_memset+0x4>
 8000364:	4770      	bx	lr

08000366 <__aeabi_memclr>:
 8000366:	2200      	movs	r2, #0
 8000368:	e7f6      	b.n	8000358 <__aeabi_memset>

0800036a <_memset$wrapper>:
 800036a:	b510      	push	{r4, lr}
 800036c:	4613      	mov	r3, r2
 800036e:	460a      	mov	r2, r1
 8000370:	4604      	mov	r4, r0
 8000372:	4619      	mov	r1, r3
 8000374:	f7ff fff0 	bl	8000358 <__aeabi_memset>
 8000378:	4620      	mov	r0, r4
 800037a:	bd10      	pop	{r4, pc}

0800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>:
 800037c:	7a01      	ldrb	r1, [r0, #8]
 800037e:	b951      	cbnz	r1, 8000396 <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata+0x1a>
 8000380:	7a41      	ldrb	r1, [r0, #9]
 8000382:	b189      	cbz	r1, 80003a8 <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata+0x2c>
 8000384:	1e49      	subs	r1, r1, #1
 8000386:	7241      	strb	r1, [r0, #9]
 8000388:	6841      	ldr	r1, [r0, #4]
 800038a:	1d0a      	adds	r2, r1, #4
 800038c:	6042      	str	r2, [r0, #4]
 800038e:	6809      	ldr	r1, [r1, #0]
 8000390:	6001      	str	r1, [r0, #0]
 8000392:	2104      	movs	r1, #4
 8000394:	7201      	strb	r1, [r0, #8]
 8000396:	b2c9      	uxtb	r1, r1
 8000398:	1e49      	subs	r1, r1, #1
 800039a:	7201      	strb	r1, [r0, #8]
 800039c:	6801      	ldr	r1, [r0, #0]
 800039e:	0e0a      	lsrs	r2, r1, #24
 80003a0:	0209      	lsls	r1, r1, #8
 80003a2:	6001      	str	r1, [r0, #0]
 80003a4:	4610      	mov	r0, r2
 80003a6:	4770      	bx	lr
 80003a8:	20b0      	movs	r0, #176	@ 0xb0
 80003aa:	4770      	bx	lr

080003ac <__ARM_unwind_cpp_prcommon>:
 80003ac:	e92d 4dff 	stmdb	sp!, {r0, r1, r2, r3, r4, r5, r6, r7, r8, sl, fp, lr}
 80003b0:	b08c      	sub	sp, #48	@ 0x30
 80003b2:	ea5f 0b00 	movs.w	fp, r0
 80003b6:	f04f 0000 	mov.w	r0, #0
 80003ba:	4616      	mov	r6, r2
 80003bc:	460d      	mov	r5, r1
 80003be:	9007      	str	r0, [sp, #28]
 80003c0:	9009      	str	r0, [sp, #36]	@ 0x24
 80003c2:	9005      	str	r0, [sp, #20]
 80003c4:	9008      	str	r0, [sp, #32]
 80003c6:	d00d      	beq.n	80003e4 <__ARM_unwind_cpp_prcommon+0x38>
 80003c8:	f1bb 0f01 	cmp.w	fp, #1
 80003cc:	d00a      	beq.n	80003e4 <__ARM_unwind_cpp_prcommon+0x38>
 80003ce:	f1bb 0f02 	cmp.w	fp, #2
 80003d2:	d001      	beq.n	80003d8 <__ARM_unwind_cpp_prcommon+0x2c>
 80003d4:	2200      	movs	r2, #0
 80003d6:	e203      	b.n	80007e0 <__ARM_unwind_cpp_prcommon+0x434>
 80003d8:	6ba8      	ldr	r0, [r5, #56]	@ 0x38
 80003da:	64a8      	str	r0, [r5, #72]	@ 0x48
 80003dc:	6be8      	ldr	r0, [r5, #60]	@ 0x3c
 80003de:	9004      	str	r0, [sp, #16]
 80003e0:	6c2c      	ldr	r4, [r5, #64]	@ 0x40
 80003e2:	e00f      	b.n	8000404 <__ARM_unwind_cpp_prcommon+0x58>
 80003e4:	f895 0050 	ldrb.w	r0, [r5, #80]	@ 0x50
 80003e8:	07c0      	lsls	r0, r0, #31
 80003ea:	6ce8      	ldr	r0, [r5, #76]	@ 0x4c
 80003ec:	9004      	str	r0, [sp, #16]
 80003ee:	d178      	bne.n	80004e2 <__ARM_unwind_cpp_prcommon+0x136>
 80003f0:	980f      	ldr	r0, [sp, #60]	@ 0x3c
 80003f2:	b118      	cbz	r0, 80003fc <__ARM_unwind_cpp_prcommon+0x50>
 80003f4:	9804      	ldr	r0, [sp, #16]
 80003f6:	6800      	ldr	r0, [r0, #0]
 80003f8:	f3c0 4007 	ubfx	r0, r0, #16, #8
 80003fc:	9904      	ldr	r1, [sp, #16]
 80003fe:	eb01 0480 	add.w	r4, r1, r0, lsl #2
 8000402:	e042      	b.n	800048a <__ARM_unwind_cpp_prcommon+0xde>
 8000404:	980f      	ldr	r0, [sp, #60]	@ 0x3c
 8000406:	2802      	cmp	r0, #2
 8000408:	d011      	beq.n	800042e <__ARM_unwind_cpp_prcommon+0x82>
 800040a:	8827      	ldrh	r7, [r4, #0]
 800040c:	2f00      	cmp	r7, #0
 800040e:	d068      	beq.n	80004e2 <__ARM_unwind_cpp_prcommon+0x136>
 8000410:	8860      	ldrh	r0, [r4, #2]
 8000412:	1d24      	adds	r4, r4, #4
 8000414:	f000 0201 	and.w	r2, r0, #1
 8000418:	4639      	mov	r1, r7
 800041a:	f362 015f 	bfi	r1, r2, #1, #31
 800041e:	b161      	cbz	r1, 800043a <__ARM_unwind_cpp_prcommon+0x8e>
 8000420:	2901      	cmp	r1, #1
 8000422:	d034      	beq.n	800048e <__ARM_unwind_cpp_prcommon+0xe2>
 8000424:	2902      	cmp	r1, #2
 8000426:	d07d      	beq.n	8000524 <__ARM_unwind_cpp_prcommon+0x178>
 8000428:	2903      	cmp	r1, #3
 800042a:	d1eb      	bne.n	8000404 <__ARM_unwind_cpp_prcommon+0x58>
 800042c:	e12f      	b.n	800068e <__ARM_unwind_cpp_prcommon+0x2e2>
 800042e:	6827      	ldr	r7, [r4, #0]
 8000430:	2f00      	cmp	r7, #0
 8000432:	d0ec      	beq.n	800040e <__ARM_unwind_cpp_prcommon+0x62>
 8000434:	6860      	ldr	r0, [r4, #4]
 8000436:	3408      	adds	r4, #8
 8000438:	e7ec      	b.n	8000414 <__ARM_unwind_cpp_prcommon+0x68>
 800043a:	f1bb 0f00 	cmp.w	fp, #0
 800043e:	d024      	beq.n	800048a <__ARM_unwind_cpp_prcommon+0xde>
 8000440:	6ca9      	ldr	r1, [r5, #72]	@ 0x48
 8000442:	2300      	movs	r3, #0
 8000444:	eb01 0800 	add.w	r8, r1, r0
 8000448:	a906      	add	r1, sp, #24
 800044a:	9100      	str	r1, [sp, #0]
 800044c:	4630      	mov	r0, r6
 800044e:	220f      	movs	r2, #15
 8000450:	4619      	mov	r1, r3
 8000452:	f000 fad6 	bl	8000a02 <_Unwind_VRS_Get>
 8000456:	9806      	ldr	r0, [sp, #24]
 8000458:	4580      	cmp	r8, r0
 800045a:	d816      	bhi.n	800048a <__ARM_unwind_cpp_prcommon+0xde>
 800045c:	eb08 0107 	add.w	r1, r8, r7
 8000460:	4281      	cmp	r1, r0
 8000462:	d912      	bls.n	800048a <__ARM_unwind_cpp_prcommon+0xde>
 8000464:	6ca9      	ldr	r1, [r5, #72]	@ 0x48
 8000466:	63a9      	str	r1, [r5, #56]	@ 0x38
 8000468:	1d20      	adds	r0, r4, #4
 800046a:	9904      	ldr	r1, [sp, #16]
 800046c:	e9c5 100f 	strd	r1, r0, [r5, #60]	@ 0x3c
 8000470:	4628      	mov	r0, r5
 8000472:	f3af 8000 	nop.w
 8000476:	2800      	cmp	r0, #0
 8000478:	d0ac      	beq.n	80003d4 <__ARM_unwind_cpp_prcommon+0x28>
 800047a:	6820      	ldr	r0, [r4, #0]
 800047c:	220f      	movs	r2, #15
 800047e:	f340 001e 	sbfx	r0, r0, #0, #31
 8000482:	4404      	add	r4, r0
 8000484:	4630      	mov	r0, r6
 8000486:	9404      	str	r4, [sp, #16]
 8000488:	e023      	b.n	80004d2 <__ARM_unwind_cpp_prcommon+0x126>
 800048a:	1d24      	adds	r4, r4, #4
 800048c:	e7ba      	b.n	8000404 <__ARM_unwind_cpp_prcommon+0x58>
 800048e:	f1bb 0f00 	cmp.w	fp, #0
 8000492:	d027      	beq.n	80004e4 <__ARM_unwind_cpp_prcommon+0x138>
 8000494:	a906      	add	r1, sp, #24
 8000496:	2300      	movs	r3, #0
 8000498:	9100      	str	r1, [sp, #0]
 800049a:	4630      	mov	r0, r6
 800049c:	220d      	movs	r2, #13
 800049e:	4619      	mov	r1, r3
 80004a0:	f000 faaf 	bl	8000a02 <_Unwind_VRS_Get>
 80004a4:	9806      	ldr	r0, [sp, #24]
 80004a6:	6a29      	ldr	r1, [r5, #32]
 80004a8:	4288      	cmp	r0, r1
 80004aa:	d16e      	bne.n	800058a <__ARM_unwind_cpp_prcommon+0x1de>
 80004ac:	6ae8      	ldr	r0, [r5, #44]	@ 0x2c
 80004ae:	42a0      	cmp	r0, r4
 80004b0:	d16b      	bne.n	800058a <__ARM_unwind_cpp_prcommon+0x1de>
 80004b2:	6820      	ldr	r0, [r4, #0]
 80004b4:	a904      	add	r1, sp, #16
 80004b6:	f340 001e 	sbfx	r0, r0, #0, #31
 80004ba:	4404      	add	r4, r0
 80004bc:	2300      	movs	r3, #0
 80004be:	9100      	str	r1, [sp, #0]
 80004c0:	4630      	mov	r0, r6
 80004c2:	220f      	movs	r2, #15
 80004c4:	9404      	str	r4, [sp, #16]
 80004c6:	4619      	mov	r1, r3
 80004c8:	f000 fa84 	bl	80009d4 <_Unwind_VRS_Set>
 80004cc:	4630      	mov	r0, r6
 80004ce:	2200      	movs	r2, #0
 80004d0:	9504      	str	r5, [sp, #16]
 80004d2:	a904      	add	r1, sp, #16
 80004d4:	2300      	movs	r3, #0
 80004d6:	9100      	str	r1, [sp, #0]
 80004d8:	4619      	mov	r1, r3
 80004da:	f000 fa7b 	bl	80009d4 <_Unwind_VRS_Set>
 80004de:	4622      	mov	r2, r4
 80004e0:	e23c      	b.n	800095c <__ARM_unwind_cpp_prcommon+0x5b0>
 80004e2:	e0d6      	b.n	8000692 <__ARM_unwind_cpp_prcommon+0x2e6>
 80004e4:	6ca9      	ldr	r1, [r5, #72]	@ 0x48
 80004e6:	2300      	movs	r3, #0
 80004e8:	eb01 0800 	add.w	r8, r1, r0
 80004ec:	a90a      	add	r1, sp, #40	@ 0x28
 80004ee:	9100      	str	r1, [sp, #0]
 80004f0:	4630      	mov	r0, r6
 80004f2:	220f      	movs	r2, #15
 80004f4:	4619      	mov	r1, r3
 80004f6:	f000 fa84 	bl	8000a02 <_Unwind_VRS_Get>
 80004fa:	980a      	ldr	r0, [sp, #40]	@ 0x28
 80004fc:	1e7f      	subs	r7, r7, #1
 80004fe:	4580      	cmp	r8, r0
 8000500:	d843      	bhi.n	800058a <__ARM_unwind_cpp_prcommon+0x1de>
 8000502:	eb08 0107 	add.w	r1, r8, r7
 8000506:	4281      	cmp	r1, r0
 8000508:	d93f      	bls.n	800058a <__ARM_unwind_cpp_prcommon+0x1de>
 800050a:	6867      	ldr	r7, [r4, #4]
 800050c:	1cb8      	adds	r0, r7, #2
 800050e:	d00e      	beq.n	800052e <__ARM_unwind_cpp_prcommon+0x182>
 8000510:	1c78      	adds	r0, r7, #1
 8000512:	d00e      	beq.n	8000532 <__ARM_unwind_cpp_prcommon+0x186>
 8000514:	6820      	ldr	r0, [r4, #0]
 8000516:	ab06      	add	r3, sp, #24
 8000518:	0fc2      	lsrs	r2, r0, #31
 800051a:	4639      	mov	r1, r7
 800051c:	4628      	mov	r0, r5
 800051e:	f3af 8000 	nop.w
 8000522:	e000      	b.n	8000526 <__ARM_unwind_cpp_prcommon+0x17a>
 8000524:	e033      	b.n	800058e <__ARM_unwind_cpp_prcommon+0x1e2>
 8000526:	b378      	cbz	r0, 8000588 <__ARM_unwind_cpp_prcommon+0x1dc>
 8000528:	2802      	cmp	r0, #2
 800052a:	d01d      	beq.n	8000568 <__ARM_unwind_cpp_prcommon+0x1bc>
 800052c:	e004      	b.n	8000538 <__ARM_unwind_cpp_prcommon+0x18c>
 800052e:	2202      	movs	r2, #2
 8000530:	e156      	b.n	80007e0 <__ARM_unwind_cpp_prcommon+0x434>
 8000532:	f105 0058 	add.w	r0, r5, #88	@ 0x58
 8000536:	9006      	str	r0, [sp, #24]
 8000538:	a904      	add	r1, sp, #16
 800053a:	2300      	movs	r3, #0
 800053c:	9100      	str	r1, [sp, #0]
 800053e:	4630      	mov	r0, r6
 8000540:	220d      	movs	r2, #13
 8000542:	4619      	mov	r1, r3
 8000544:	f000 fa5d 	bl	8000a02 <_Unwind_VRS_Get>
 8000548:	9804      	ldr	r0, [sp, #16]
 800054a:	62ec      	str	r4, [r5, #44]	@ 0x2c
 800054c:	6228      	str	r0, [r5, #32]
 800054e:	9806      	ldr	r0, [sp, #24]
 8000550:	6268      	str	r0, [r5, #36]	@ 0x24
 8000552:	6820      	ldr	r0, [r4, #0]
 8000554:	2102      	movs	r1, #2
 8000556:	f340 001e 	sbfx	r0, r0, #0, #31
 800055a:	1902      	adds	r2, r0, r4
 800055c:	4628      	mov	r0, r5
 800055e:	f7ff fe31 	bl	80001c4 <_Unwind_Activity>
 8000562:	463a      	mov	r2, r7
 8000564:	2180      	movs	r1, #128	@ 0x80
 8000566:	e05f      	b.n	8000628 <__ARM_unwind_cpp_prcommon+0x27c>
 8000568:	a904      	add	r1, sp, #16
 800056a:	2300      	movs	r3, #0
 800056c:	9100      	str	r1, [sp, #0]
 800056e:	4630      	mov	r0, r6
 8000570:	220d      	movs	r2, #13
 8000572:	4619      	mov	r1, r3
 8000574:	f000 fa45 	bl	8000a02 <_Unwind_VRS_Get>
 8000578:	9804      	ldr	r0, [sp, #16]
 800057a:	62ec      	str	r4, [r5, #44]	@ 0x2c
 800057c:	6228      	str	r0, [r5, #32]
 800057e:	9806      	ldr	r0, [sp, #24]
 8000580:	62a8      	str	r0, [r5, #40]	@ 0x28
 8000582:	f105 0028 	add.w	r0, r5, #40	@ 0x28
 8000586:	e7e3      	b.n	8000550 <__ARM_unwind_cpp_prcommon+0x1a4>
 8000588:	e7ff      	b.n	800058a <__ARM_unwind_cpp_prcommon+0x1de>
 800058a:	3408      	adds	r4, #8
 800058c:	e73a      	b.n	8000404 <__ARM_unwind_cpp_prcommon+0x58>
 800058e:	6821      	ldr	r1, [r4, #0]
 8000590:	9106      	str	r1, [sp, #24]
 8000592:	f021 4800 	bic.w	r8, r1, #2147483648	@ 0x80000000
 8000596:	f1bb 0f00 	cmp.w	fp, #0
 800059a:	d010      	beq.n	80005be <__ARM_unwind_cpp_prcommon+0x212>
 800059c:	a90a      	add	r1, sp, #40	@ 0x28
 800059e:	2300      	movs	r3, #0
 80005a0:	9100      	str	r1, [sp, #0]
 80005a2:	4630      	mov	r0, r6
 80005a4:	220d      	movs	r2, #13
 80005a6:	4619      	mov	r1, r3
 80005a8:	f000 fa2b 	bl	8000a02 <_Unwind_VRS_Get>
 80005ac:	980a      	ldr	r0, [sp, #40]	@ 0x28
 80005ae:	6a29      	ldr	r1, [r5, #32]
 80005b0:	4288      	cmp	r0, r1
 80005b2:	d140      	bne.n	8000636 <__ARM_unwind_cpp_prcommon+0x28a>
 80005b4:	6ae8      	ldr	r0, [r5, #44]	@ 0x2c
 80005b6:	42a0      	cmp	r0, r4
 80005b8:	d13d      	bne.n	8000636 <__ARM_unwind_cpp_prcommon+0x28a>
 80005ba:	2001      	movs	r0, #1
 80005bc:	e03c      	b.n	8000638 <__ARM_unwind_cpp_prcommon+0x28c>
 80005be:	6ca9      	ldr	r1, [r5, #72]	@ 0x48
 80005c0:	1e40      	subs	r0, r0, #1
 80005c2:	eb01 0a00 	add.w	sl, r1, r0
 80005c6:	a90a      	add	r1, sp, #40	@ 0x28
 80005c8:	2300      	movs	r3, #0
 80005ca:	9100      	str	r1, [sp, #0]
 80005cc:	4630      	mov	r0, r6
 80005ce:	220f      	movs	r2, #15
 80005d0:	4619      	mov	r1, r3
 80005d2:	f000 fa16 	bl	8000a02 <_Unwind_VRS_Get>
 80005d6:	980a      	ldr	r0, [sp, #40]	@ 0x28
 80005d8:	4582      	cmp	sl, r0
 80005da:	d83a      	bhi.n	8000652 <__ARM_unwind_cpp_prcommon+0x2a6>
 80005dc:	eb0a 0107 	add.w	r1, sl, r7
 80005e0:	4281      	cmp	r1, r0
 80005e2:	d936      	bls.n	8000652 <__ARM_unwind_cpp_prcommon+0x2a6>
 80005e4:	f104 0a04 	add.w	sl, r4, #4
 80005e8:	2700      	movs	r7, #0
 80005ea:	e00a      	b.n	8000602 <__ARM_unwind_cpp_prcommon+0x256>
 80005ec:	466b      	mov	r3, sp
 80005ee:	2200      	movs	r2, #0
 80005f0:	4628      	mov	r0, r5
 80005f2:	f8da 1000 	ldr.w	r1, [sl]
 80005f6:	f3af 8000 	nop.w
 80005fa:	b920      	cbnz	r0, 8000606 <__ARM_unwind_cpp_prcommon+0x25a>
 80005fc:	f10a 0a04 	add.w	sl, sl, #4
 8000600:	1c7f      	adds	r7, r7, #1
 8000602:	4547      	cmp	r7, r8
 8000604:	d3f2      	bcc.n	80005ec <__ARM_unwind_cpp_prcommon+0x240>
 8000606:	4547      	cmp	r7, r8
 8000608:	d123      	bne.n	8000652 <__ARM_unwind_cpp_prcommon+0x2a6>
 800060a:	a904      	add	r1, sp, #16
 800060c:	2300      	movs	r3, #0
 800060e:	9100      	str	r1, [sp, #0]
 8000610:	4630      	mov	r0, r6
 8000612:	220d      	movs	r2, #13
 8000614:	4619      	mov	r1, r3
 8000616:	f000 f9f4 	bl	8000a02 <_Unwind_VRS_Get>
 800061a:	9804      	ldr	r0, [sp, #16]
 800061c:	62ec      	str	r4, [r5, #44]	@ 0x2c
 800061e:	6228      	str	r0, [r5, #32]
 8000620:	2000      	movs	r0, #0
 8000622:	4ad2      	ldr	r2, [pc, #840]	@ (800096c <__ARM_unwind_cpp_prcommon+0x5c0>)
 8000624:	2102      	movs	r1, #2
 8000626:	6268      	str	r0, [r5, #36]	@ 0x24
 8000628:	4628      	mov	r0, r5
 800062a:	f7ff fdcb 	bl	80001c4 <_Unwind_Activity>
 800062e:	2006      	movs	r0, #6
 8000630:	b010      	add	sp, #64	@ 0x40
 8000632:	e8bd 8df0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, sl, fp, pc}
 8000636:	2000      	movs	r0, #0
 8000638:	b158      	cbz	r0, 8000652 <__ARM_unwind_cpp_prcommon+0x2a6>
 800063a:	2000      	movs	r0, #0
 800063c:	e9c5 800a 	strd	r8, r0, [r5, #40]	@ 0x28
 8000640:	2004      	movs	r0, #4
 8000642:	6328      	str	r0, [r5, #48]	@ 0x30
 8000644:	1d20      	adds	r0, r4, #4
 8000646:	6368      	str	r0, [r5, #52]	@ 0x34
 8000648:	9806      	ldr	r0, [sp, #24]
 800064a:	4540      	cmp	r0, r8
 800064c:	d106      	bne.n	800065c <__ARM_unwind_cpp_prcommon+0x2b0>
 800064e:	2001      	movs	r0, #1
 8000650:	9007      	str	r0, [sp, #28]
 8000652:	9806      	ldr	r0, [sp, #24]
 8000654:	4540      	cmp	r0, r8
 8000656:	d115      	bne.n	8000684 <__ARM_unwind_cpp_prcommon+0x2d8>
 8000658:	2000      	movs	r0, #0
 800065a:	e014      	b.n	8000686 <__ARM_unwind_cpp_prcommon+0x2da>
 800065c:	eb04 0088 	add.w	r0, r4, r8, lsl #2
 8000660:	2200      	movs	r2, #0
 8000662:	f850 1f04 	ldr.w	r1, [r0, #4]!
 8000666:	4613      	mov	r3, r2
 8000668:	f341 011e 	sbfx	r1, r1, #0, #31
 800066c:	180c      	adds	r4, r1, r0
 800066e:	a904      	add	r1, sp, #16
 8000670:	9100      	str	r1, [sp, #0]
 8000672:	4630      	mov	r0, r6
 8000674:	9504      	str	r5, [sp, #16]
 8000676:	4611      	mov	r1, r2
 8000678:	f000 f9ac 	bl	80009d4 <_Unwind_VRS_Set>
 800067c:	4630      	mov	r0, r6
 800067e:	220f      	movs	r2, #15
 8000680:	9404      	str	r4, [sp, #16]
 8000682:	e164      	b.n	800094e <__ARM_unwind_cpp_prcommon+0x5a2>
 8000684:	2004      	movs	r0, #4
 8000686:	eb00 0088 	add.w	r0, r0, r8, lsl #2
 800068a:	4404      	add	r4, r0
 800068c:	e6fd      	b.n	800048a <__ARM_unwind_cpp_prcommon+0xde>
 800068e:	2201      	movs	r2, #1
 8000690:	e0a6      	b.n	80007e0 <__ARM_unwind_cpp_prcommon+0x434>
 8000692:	9804      	ldr	r0, [sp, #16]
 8000694:	6800      	ldr	r0, [r0, #0]
 8000696:	9001      	str	r0, [sp, #4]
 8000698:	9804      	ldr	r0, [sp, #16]
 800069a:	1d00      	adds	r0, r0, #4
 800069c:	9002      	str	r0, [sp, #8]
 800069e:	980f      	ldr	r0, [sp, #60]	@ 0x3c
 80006a0:	b308      	cbz	r0, 80006e6 <__ARM_unwind_cpp_prcommon+0x33a>
 80006a2:	9801      	ldr	r0, [sp, #4]
 80006a4:	0c01      	lsrs	r1, r0, #16
 80006a6:	0400      	lsls	r0, r0, #16
 80006a8:	9001      	str	r0, [sp, #4]
 80006aa:	f88d 100d 	strb.w	r1, [sp, #13]
 80006ae:	2002      	movs	r0, #2
 80006b0:	f88d 000c 	strb.w	r0, [sp, #12]
 80006b4:	a801      	add	r0, sp, #4
 80006b6:	f7ff fe61 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 80006ba:	4604      	mov	r4, r0
 80006bc:	28b0      	cmp	r0, #176	@ 0xb0
 80006be:	d01a      	beq.n	80006f6 <__ARM_unwind_cpp_prcommon+0x34a>
 80006c0:	2c3f      	cmp	r4, #63	@ 0x3f
 80006c2:	d841      	bhi.n	8000748 <__ARM_unwind_cpp_prcommon+0x39c>
 80006c4:	f000 013f 	and.w	r1, r0, #63	@ 0x3f
 80006c8:	2004      	movs	r0, #4
 80006ca:	eb00 0781 	add.w	r7, r0, r1, lsl #2
 80006ce:	a906      	add	r1, sp, #24
 80006d0:	240d      	movs	r4, #13
 80006d2:	2300      	movs	r3, #0
 80006d4:	9100      	str	r1, [sp, #0]
 80006d6:	4630      	mov	r0, r6
 80006d8:	4622      	mov	r2, r4
 80006da:	4619      	mov	r1, r3
 80006dc:	f000 f991 	bl	8000a02 <_Unwind_VRS_Get>
 80006e0:	9806      	ldr	r0, [sp, #24]
 80006e2:	4438      	add	r0, r7
 80006e4:	e042      	b.n	800076c <__ARM_unwind_cpp_prcommon+0x3c0>
 80006e6:	2000      	movs	r0, #0
 80006e8:	f88d 000d 	strb.w	r0, [sp, #13]
 80006ec:	9801      	ldr	r0, [sp, #4]
 80006ee:	0200      	lsls	r0, r0, #8
 80006f0:	9001      	str	r0, [sp, #4]
 80006f2:	2003      	movs	r0, #3
 80006f4:	e7dc      	b.n	80006b0 <__ARM_unwind_cpp_prcommon+0x304>
 80006f6:	9809      	ldr	r0, [sp, #36]	@ 0x24
 80006f8:	b9b0      	cbnz	r0, 8000728 <__ARM_unwind_cpp_prcommon+0x37c>
 80006fa:	9805      	ldr	r0, [sp, #20]
 80006fc:	2800      	cmp	r0, #0
 80006fe:	d0c6      	beq.n	800068e <__ARM_unwind_cpp_prcommon+0x2e2>
 8000700:	a804      	add	r0, sp, #16
 8000702:	2300      	movs	r3, #0
 8000704:	9000      	str	r0, [sp, #0]
 8000706:	220e      	movs	r2, #14
 8000708:	4619      	mov	r1, r3
 800070a:	4630      	mov	r0, r6
 800070c:	f000 f979 	bl	8000a02 <_Unwind_VRS_Get>
 8000710:	9904      	ldr	r1, [sp, #16]
 8000712:	9105      	str	r1, [sp, #20]
 8000714:	a905      	add	r1, sp, #20
 8000716:	2300      	movs	r3, #0
 8000718:	9100      	str	r1, [sp, #0]
 800071a:	4630      	mov	r0, r6
 800071c:	220f      	movs	r2, #15
 800071e:	4619      	mov	r1, r3
 8000720:	f000 f958 	bl	80009d4 <_Unwind_VRS_Set>
 8000724:	2001      	movs	r0, #1
 8000726:	9008      	str	r0, [sp, #32]
 8000728:	9807      	ldr	r0, [sp, #28]
 800072a:	2800      	cmp	r0, #0
 800072c:	d070      	beq.n	8000810 <__ARM_unwind_cpp_prcommon+0x464>
 800072e:	2200      	movs	r2, #0
 8000730:	a904      	add	r1, sp, #16
 8000732:	9100      	str	r1, [sp, #0]
 8000734:	4630      	mov	r0, r6
 8000736:	4613      	mov	r3, r2
 8000738:	9504      	str	r5, [sp, #16]
 800073a:	4611      	mov	r1, r2
 800073c:	f000 f94a 	bl	80009d4 <_Unwind_VRS_Set>
 8000740:	9808      	ldr	r0, [sp, #32]
 8000742:	2800      	cmp	r0, #0
 8000744:	d078      	beq.n	8000838 <__ARM_unwind_cpp_prcommon+0x48c>
 8000746:	e0fe      	b.n	8000946 <__ARM_unwind_cpp_prcommon+0x59a>
 8000748:	2c7f      	cmp	r4, #127	@ 0x7f
 800074a:	d819      	bhi.n	8000780 <__ARM_unwind_cpp_prcommon+0x3d4>
 800074c:	f000 013f 	and.w	r1, r0, #63	@ 0x3f
 8000750:	2004      	movs	r0, #4
 8000752:	eb00 0781 	add.w	r7, r0, r1, lsl #2
 8000756:	a906      	add	r1, sp, #24
 8000758:	240d      	movs	r4, #13
 800075a:	2300      	movs	r3, #0
 800075c:	9100      	str	r1, [sp, #0]
 800075e:	4630      	mov	r0, r6
 8000760:	4622      	mov	r2, r4
 8000762:	4619      	mov	r1, r3
 8000764:	f000 f94d 	bl	8000a02 <_Unwind_VRS_Get>
 8000768:	9806      	ldr	r0, [sp, #24]
 800076a:	1bc0      	subs	r0, r0, r7
 800076c:	9004      	str	r0, [sp, #16]
 800076e:	a804      	add	r0, sp, #16
 8000770:	2300      	movs	r3, #0
 8000772:	9000      	str	r0, [sp, #0]
 8000774:	4622      	mov	r2, r4
 8000776:	4619      	mov	r1, r3
 8000778:	4630      	mov	r0, r6
 800077a:	f000 f92b 	bl	80009d4 <_Unwind_VRS_Set>
 800077e:	e799      	b.n	80006b4 <__ARM_unwind_cpp_prcommon+0x308>
 8000780:	2c8f      	cmp	r4, #143	@ 0x8f
 8000782:	d81a      	bhi.n	80007ba <__ARM_unwind_cpp_prcommon+0x40e>
 8000784:	0700      	lsls	r0, r0, #28
 8000786:	0c04      	lsrs	r4, r0, #16
 8000788:	a801      	add	r0, sp, #4
 800078a:	f7ff fdf7 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 800078e:	ea54 1400 	orrs.w	r4, r4, r0, lsl #4
 8000792:	f43f aecc 	beq.w	800052e <__ARM_unwind_cpp_prcommon+0x182>
 8000796:	2300      	movs	r3, #0
 8000798:	4622      	mov	r2, r4
 800079a:	4619      	mov	r1, r3
 800079c:	4630      	mov	r0, r6
 800079e:	f000 f947 	bl	8000a30 <_Unwind_VRS_Pop>
 80007a2:	b108      	cbz	r0, 80007a8 <__ARM_unwind_cpp_prcommon+0x3fc>
 80007a4:	2203      	movs	r2, #3
 80007a6:	e01b      	b.n	80007e0 <__ARM_unwind_cpp_prcommon+0x434>
 80007a8:	0420      	lsls	r0, r4, #16
 80007aa:	d501      	bpl.n	80007b0 <__ARM_unwind_cpp_prcommon+0x404>
 80007ac:	2001      	movs	r0, #1
 80007ae:	9009      	str	r0, [sp, #36]	@ 0x24
 80007b0:	0460      	lsls	r0, r4, #17
 80007b2:	d5e4      	bpl.n	800077e <__ARM_unwind_cpp_prcommon+0x3d2>
 80007b4:	2001      	movs	r0, #1
 80007b6:	9005      	str	r0, [sp, #20]
 80007b8:	e77c      	b.n	80006b4 <__ARM_unwind_cpp_prcommon+0x308>
 80007ba:	2c9f      	cmp	r4, #159	@ 0x9f
 80007bc:	d816      	bhi.n	80007ec <__ARM_unwind_cpp_prcommon+0x440>
 80007be:	f000 020f 	and.w	r2, r0, #15
 80007c2:	2a0d      	cmp	r2, #13
 80007c4:	d00b      	beq.n	80007de <__ARM_unwind_cpp_prcommon+0x432>
 80007c6:	2a0f      	cmp	r2, #15
 80007c8:	d009      	beq.n	80007de <__ARM_unwind_cpp_prcommon+0x432>
 80007ca:	a906      	add	r1, sp, #24
 80007cc:	2300      	movs	r3, #0
 80007ce:	9100      	str	r1, [sp, #0]
 80007d0:	240d      	movs	r4, #13
 80007d2:	4630      	mov	r0, r6
 80007d4:	4619      	mov	r1, r3
 80007d6:	f000 f914 	bl	8000a02 <_Unwind_VRS_Get>
 80007da:	9806      	ldr	r0, [sp, #24]
 80007dc:	e7c6      	b.n	800076c <__ARM_unwind_cpp_prcommon+0x3c0>
 80007de:	2204      	movs	r2, #4
 80007e0:	2101      	movs	r1, #1
 80007e2:	4628      	mov	r0, r5
 80007e4:	f7ff fcee 	bl	80001c4 <_Unwind_Activity>
 80007e8:	2009      	movs	r0, #9
 80007ea:	e721      	b.n	8000630 <__ARM_unwind_cpp_prcommon+0x284>
 80007ec:	2caf      	cmp	r4, #175	@ 0xaf
 80007ee:	d810      	bhi.n	8000812 <__ARM_unwind_cpp_prcommon+0x466>
 80007f0:	f004 0007 	and.w	r0, r4, #7
 80007f4:	2101      	movs	r1, #1
 80007f6:	1c40      	adds	r0, r0, #1
 80007f8:	4081      	lsls	r1, r0
 80007fa:	010a      	lsls	r2, r1, #4
 80007fc:	3a10      	subs	r2, #16
 80007fe:	0720      	lsls	r0, r4, #28
 8000800:	d503      	bpl.n	800080a <__ARM_unwind_cpp_prcommon+0x45e>
 8000802:	2001      	movs	r0, #1
 8000804:	f442 4280 	orr.w	r2, r2, #16384	@ 0x4000
 8000808:	9005      	str	r0, [sp, #20]
 800080a:	2300      	movs	r3, #0
 800080c:	4619      	mov	r1, r3
 800080e:	e058      	b.n	80008c2 <__ARM_unwind_cpp_prcommon+0x516>
 8000810:	e0aa      	b.n	8000968 <__ARM_unwind_cpp_prcommon+0x5bc>
 8000812:	2cb7      	cmp	r4, #183	@ 0xb7
 8000814:	d835      	bhi.n	8000882 <__ARM_unwind_cpp_prcommon+0x4d6>
 8000816:	2cb1      	cmp	r4, #177	@ 0xb1
 8000818:	d00f      	beq.n	800083a <__ARM_unwind_cpp_prcommon+0x48e>
 800081a:	2cb2      	cmp	r4, #178	@ 0xb2
 800081c:	d015      	beq.n	800084a <__ARM_unwind_cpp_prcommon+0x49e>
 800081e:	28b3      	cmp	r0, #179	@ 0xb3
 8000820:	d1dd      	bne.n	80007de <__ARM_unwind_cpp_prcommon+0x432>
 8000822:	a801      	add	r0, sp, #4
 8000824:	f7ff fdaa 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 8000828:	f000 010f 	and.w	r1, r0, #15
 800082c:	f000 00f0 	and.w	r0, r0, #240	@ 0xf0
 8000830:	1c49      	adds	r1, r1, #1
 8000832:	ea41 3200 	orr.w	r2, r1, r0, lsl #12
 8000836:	e02b      	b.n	8000890 <__ARM_unwind_cpp_prcommon+0x4e4>
 8000838:	e073      	b.n	8000922 <__ARM_unwind_cpp_prcommon+0x576>
 800083a:	a801      	add	r0, sp, #4
 800083c:	f7ff fd9e 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 8000840:	0002      	movs	r2, r0
 8000842:	d0cc      	beq.n	80007de <__ARM_unwind_cpp_prcommon+0x432>
 8000844:	2a0f      	cmp	r2, #15
 8000846:	d9e0      	bls.n	800080a <__ARM_unwind_cpp_prcommon+0x45e>
 8000848:	e7c9      	b.n	80007de <__ARM_unwind_cpp_prcommon+0x432>
 800084a:	2700      	movs	r7, #0
 800084c:	463c      	mov	r4, r7
 800084e:	a801      	add	r0, sp, #4
 8000850:	f7ff fd94 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 8000854:	f000 017f 	and.w	r1, r0, #127	@ 0x7f
 8000858:	40a1      	lsls	r1, r4
 800085a:	430f      	orrs	r7, r1
 800085c:	0600      	lsls	r0, r0, #24
 800085e:	d501      	bpl.n	8000864 <__ARM_unwind_cpp_prcommon+0x4b8>
 8000860:	1de4      	adds	r4, r4, #7
 8000862:	e7f4      	b.n	800084e <__ARM_unwind_cpp_prcommon+0x4a2>
 8000864:	a906      	add	r1, sp, #24
 8000866:	240d      	movs	r4, #13
 8000868:	2300      	movs	r3, #0
 800086a:	9100      	str	r1, [sp, #0]
 800086c:	4630      	mov	r0, r6
 800086e:	4622      	mov	r2, r4
 8000870:	4619      	mov	r1, r3
 8000872:	f000 f8c6 	bl	8000a02 <_Unwind_VRS_Get>
 8000876:	9806      	ldr	r0, [sp, #24]
 8000878:	eb00 0087 	add.w	r0, r0, r7, lsl #2
 800087c:	f500 7001 	add.w	r0, r0, #516	@ 0x204
 8000880:	e774      	b.n	800076c <__ARM_unwind_cpp_prcommon+0x3c0>
 8000882:	2cbf      	cmp	r4, #191	@ 0xbf
 8000884:	d807      	bhi.n	8000896 <__ARM_unwind_cpp_prcommon+0x4ea>
 8000886:	f000 0007 	and.w	r0, r0, #7
 800088a:	1c40      	adds	r0, r0, #1
 800088c:	f440 2200 	orr.w	r2, r0, #524288	@ 0x80000
 8000890:	2301      	movs	r3, #1
 8000892:	2101      	movs	r1, #1
 8000894:	e015      	b.n	80008c2 <__ARM_unwind_cpp_prcommon+0x516>
 8000896:	2cc7      	cmp	r4, #199	@ 0xc7
 8000898:	d825      	bhi.n	80008e6 <__ARM_unwind_cpp_prcommon+0x53a>
 800089a:	d109      	bne.n	80008b0 <__ARM_unwind_cpp_prcommon+0x504>
 800089c:	a801      	add	r0, sp, #4
 800089e:	f7ff fd6d 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 80008a2:	0002      	movs	r2, r0
 80008a4:	d09b      	beq.n	80007de <__ARM_unwind_cpp_prcommon+0x432>
 80008a6:	2a0f      	cmp	r2, #15
 80008a8:	d899      	bhi.n	80007de <__ARM_unwind_cpp_prcommon+0x432>
 80008aa:	2300      	movs	r3, #0
 80008ac:	2104      	movs	r1, #4
 80008ae:	e008      	b.n	80008c2 <__ARM_unwind_cpp_prcommon+0x516>
 80008b0:	2cc6      	cmp	r4, #198	@ 0xc6
 80008b2:	d00d      	beq.n	80008d0 <__ARM_unwind_cpp_prcommon+0x524>
 80008b4:	f000 0007 	and.w	r0, r0, #7
 80008b8:	1c40      	adds	r0, r0, #1
 80008ba:	f440 2220 	orr.w	r2, r0, #655360	@ 0xa0000
 80008be:	2303      	movs	r3, #3
 80008c0:	4619      	mov	r1, r3
 80008c2:	4630      	mov	r0, r6
 80008c4:	f000 f8b4 	bl	8000a30 <_Unwind_VRS_Pop>
 80008c8:	2800      	cmp	r0, #0
 80008ca:	f43f af58 	beq.w	800077e <__ARM_unwind_cpp_prcommon+0x3d2>
 80008ce:	e769      	b.n	80007a4 <__ARM_unwind_cpp_prcommon+0x3f8>
 80008d0:	a801      	add	r0, sp, #4
 80008d2:	f7ff fd53 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 80008d6:	f000 010f 	and.w	r1, r0, #15
 80008da:	f000 00f0 	and.w	r0, r0, #240	@ 0xf0
 80008de:	1c49      	adds	r1, r1, #1
 80008e0:	ea41 3200 	orr.w	r2, r1, r0, lsl #12
 80008e4:	e7eb      	b.n	80008be <__ARM_unwind_cpp_prcommon+0x512>
 80008e6:	2cc8      	cmp	r4, #200	@ 0xc8
 80008e8:	d00b      	beq.n	8000902 <__ARM_unwind_cpp_prcommon+0x556>
 80008ea:	2cc9      	cmp	r4, #201	@ 0xc9
 80008ec:	d009      	beq.n	8000902 <__ARM_unwind_cpp_prcommon+0x556>
 80008ee:	2ccf      	cmp	r4, #207	@ 0xcf
 80008f0:	d9aa      	bls.n	8000848 <__ARM_unwind_cpp_prcommon+0x49c>
 80008f2:	2cd7      	cmp	r4, #215	@ 0xd7
 80008f4:	d8a8      	bhi.n	8000848 <__ARM_unwind_cpp_prcommon+0x49c>
 80008f6:	f000 0007 	and.w	r0, r0, #7
 80008fa:	1c40      	adds	r0, r0, #1
 80008fc:	f440 2200 	orr.w	r2, r0, #524288	@ 0x80000
 8000900:	e00d      	b.n	800091e <__ARM_unwind_cpp_prcommon+0x572>
 8000902:	a801      	add	r0, sp, #4
 8000904:	f7ff fd3a 	bl	800037c <_ZN33_INTERNAL_11_unwind_pr_c_0170a69416next_unwind_byteEP6uwdata>
 8000908:	f000 010f 	and.w	r1, r0, #15
 800090c:	1c49      	adds	r1, r1, #1
 800090e:	f000 00f0 	and.w	r0, r0, #240	@ 0xf0
 8000912:	ea41 3200 	orr.w	r2, r1, r0, lsl #12
 8000916:	2cc8      	cmp	r4, #200	@ 0xc8
 8000918:	d101      	bne.n	800091e <__ARM_unwind_cpp_prcommon+0x572>
 800091a:	f502 1280 	add.w	r2, r2, #1048576	@ 0x100000
 800091e:	2305      	movs	r3, #5
 8000920:	e7b7      	b.n	8000892 <__ARM_unwind_cpp_prcommon+0x4e6>
 8000922:	a804      	add	r0, sp, #16
 8000924:	2300      	movs	r3, #0
 8000926:	9000      	str	r0, [sp, #0]
 8000928:	220f      	movs	r2, #15
 800092a:	4619      	mov	r1, r3
 800092c:	4630      	mov	r0, r6
 800092e:	f000 f868 	bl	8000a02 <_Unwind_VRS_Get>
 8000932:	9904      	ldr	r1, [sp, #16]
 8000934:	9105      	str	r1, [sp, #20]
 8000936:	a905      	add	r1, sp, #20
 8000938:	2300      	movs	r3, #0
 800093a:	9100      	str	r1, [sp, #0]
 800093c:	4630      	mov	r0, r6
 800093e:	220e      	movs	r2, #14
 8000940:	4619      	mov	r1, r3
 8000942:	f000 f847 	bl	80009d4 <_Unwind_VRS_Set>
 8000946:	4909      	ldr	r1, [pc, #36]	@ (800096c <__ARM_unwind_cpp_prcommon+0x5c0>)
 8000948:	4630      	mov	r0, r6
 800094a:	220f      	movs	r2, #15
 800094c:	9104      	str	r1, [sp, #16]
 800094e:	a904      	add	r1, sp, #16
 8000950:	2300      	movs	r3, #0
 8000952:	9100      	str	r1, [sp, #0]
 8000954:	4619      	mov	r1, r3
 8000956:	f000 f83d 	bl	80009d4 <_Unwind_VRS_Set>
 800095a:	4a04      	ldr	r2, [pc, #16]	@ (800096c <__ARM_unwind_cpp_prcommon+0x5c0>)
 800095c:	2103      	movs	r1, #3
 800095e:	4628      	mov	r0, r5
 8000960:	f7ff fc30 	bl	80001c4 <_Unwind_Activity>
 8000964:	2007      	movs	r0, #7
 8000966:	e663      	b.n	8000630 <__ARM_unwind_cpp_prcommon+0x284>
 8000968:	2008      	movs	r0, #8
 800096a:	e661      	b.n	8000630 <__ARM_unwind_cpp_prcommon+0x284>
 800096c:	00000000 	.word	0x00000000

08000970 <__aeabi_uldivmod>:
 8000970:	e92d 5ff0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, ip, lr}
 8000974:	4605      	mov	r5, r0
 8000976:	2000      	movs	r0, #0
 8000978:	4692      	mov	sl, r2
 800097a:	469b      	mov	fp, r3
 800097c:	4688      	mov	r8, r1
 800097e:	4606      	mov	r6, r0
 8000980:	4681      	mov	r9, r0
 8000982:	2440      	movs	r4, #64	@ 0x40
 8000984:	e01b      	b.n	80009be <__aeabi_uldivmod+0x4e>
 8000986:	4628      	mov	r0, r5
 8000988:	4641      	mov	r1, r8
 800098a:	4647      	mov	r7, r8
 800098c:	4622      	mov	r2, r4
 800098e:	f7ff fcd3 	bl	8000338 <__aeabi_llsr>
 8000992:	4653      	mov	r3, sl
 8000994:	465a      	mov	r2, fp
 8000996:	1ac0      	subs	r0, r0, r3
 8000998:	4191      	sbcs	r1, r2
 800099a:	d310      	bcc.n	80009be <__aeabi_uldivmod+0x4e>
 800099c:	4611      	mov	r1, r2
 800099e:	4618      	mov	r0, r3
 80009a0:	4622      	mov	r2, r4
 80009a2:	f000 fa0f 	bl	8000dc4 <__aeabi_llsl>
 80009a6:	1a2d      	subs	r5, r5, r0
 80009a8:	eb67 0801 	sbc.w	r8, r7, r1
 80009ac:	464f      	mov	r7, r9
 80009ae:	4622      	mov	r2, r4
 80009b0:	2001      	movs	r0, #1
 80009b2:	2100      	movs	r1, #0
 80009b4:	f000 fa06 	bl	8000dc4 <__aeabi_llsl>
 80009b8:	eb17 0900 	adds.w	r9, r7, r0
 80009bc:	414e      	adcs	r6, r1
 80009be:	1e20      	subs	r0, r4, #0
 80009c0:	f1a4 0401 	sub.w	r4, r4, #1
 80009c4:	dcdf      	bgt.n	8000986 <__aeabi_uldivmod+0x16>
 80009c6:	4648      	mov	r0, r9
 80009c8:	4631      	mov	r1, r6
 80009ca:	462a      	mov	r2, r5
 80009cc:	4643      	mov	r3, r8
 80009ce:	e8bd 9ff0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, ip, pc}
	...

080009d4 <_Unwind_VRS_Set>:
 80009d4:	b510      	push	{r4, lr}
 80009d6:	9c02      	ldr	r4, [sp, #8]
 80009d8:	b131      	cbz	r1, 80009e8 <_Unwind_VRS_Set+0x14>
 80009da:	2901      	cmp	r1, #1
 80009dc:	d00d      	beq.n	80009fa <_Unwind_VRS_Set+0x26>
 80009de:	2903      	cmp	r1, #3
 80009e0:	d00b      	beq.n	80009fa <_Unwind_VRS_Set+0x26>
 80009e2:	2904      	cmp	r1, #4
 80009e4:	d10b      	bne.n	80009fe <_Unwind_VRS_Set+0x2a>
 80009e6:	e008      	b.n	80009fa <_Unwind_VRS_Set+0x26>
 80009e8:	b94b      	cbnz	r3, 80009fe <_Unwind_VRS_Set+0x2a>
 80009ea:	2a0f      	cmp	r2, #15
 80009ec:	d807      	bhi.n	80009fe <_Unwind_VRS_Set+0x2a>
 80009ee:	eb00 0082 	add.w	r0, r0, r2, lsl #2
 80009f2:	6821      	ldr	r1, [r4, #0]
 80009f4:	6041      	str	r1, [r0, #4]
 80009f6:	2000      	movs	r0, #0
 80009f8:	bd10      	pop	{r4, pc}
 80009fa:	2001      	movs	r0, #1
 80009fc:	bd10      	pop	{r4, pc}
 80009fe:	2002      	movs	r0, #2
 8000a00:	bd10      	pop	{r4, pc}

08000a02 <_Unwind_VRS_Get>:
 8000a02:	b510      	push	{r4, lr}
 8000a04:	9c02      	ldr	r4, [sp, #8]
 8000a06:	b131      	cbz	r1, 8000a16 <_Unwind_VRS_Get+0x14>
 8000a08:	2901      	cmp	r1, #1
 8000a0a:	d00d      	beq.n	8000a28 <_Unwind_VRS_Get+0x26>
 8000a0c:	2903      	cmp	r1, #3
 8000a0e:	d00b      	beq.n	8000a28 <_Unwind_VRS_Get+0x26>
 8000a10:	2904      	cmp	r1, #4
 8000a12:	d10b      	bne.n	8000a2c <_Unwind_VRS_Get+0x2a>
 8000a14:	e008      	b.n	8000a28 <_Unwind_VRS_Get+0x26>
 8000a16:	b94b      	cbnz	r3, 8000a2c <_Unwind_VRS_Get+0x2a>
 8000a18:	2a0f      	cmp	r2, #15
 8000a1a:	d807      	bhi.n	8000a2c <_Unwind_VRS_Get+0x2a>
 8000a1c:	eb00 0082 	add.w	r0, r0, r2, lsl #2
 8000a20:	6840      	ldr	r0, [r0, #4]
 8000a22:	6020      	str	r0, [r4, #0]
 8000a24:	2000      	movs	r0, #0
 8000a26:	bd10      	pop	{r4, pc}
 8000a28:	2001      	movs	r0, #1
 8000a2a:	bd10      	pop	{r4, pc}
 8000a2c:	2002      	movs	r0, #2
 8000a2e:	bd10      	pop	{r4, pc}

08000a30 <_Unwind_VRS_Pop>:
 8000a30:	e92d 4df0 	stmdb	sp!, {r4, r5, r6, r7, r8, sl, fp, lr}
 8000a34:	b0c0      	sub	sp, #256	@ 0x100
 8000a36:	4698      	mov	r8, r3
 8000a38:	4604      	mov	r4, r0
 8000a3a:	b131      	cbz	r1, 8000a4a <_Unwind_VRS_Pop+0x1a>
 8000a3c:	2901      	cmp	r1, #1
 8000a3e:	d018      	beq.n	8000a72 <_Unwind_VRS_Pop+0x42>
 8000a40:	2903      	cmp	r1, #3
 8000a42:	d079      	beq.n	8000b38 <_Unwind_VRS_Pop+0x108>
 8000a44:	2904      	cmp	r1, #4
 8000a46:	d179      	bne.n	8000b3c <_Unwind_VRS_Pop+0x10c>
 8000a48:	e076      	b.n	8000b38 <_Unwind_VRS_Pop+0x108>
 8000a4a:	f1b8 0f00 	cmp.w	r8, #0
 8000a4e:	d175      	bne.n	8000b3c <_Unwind_VRS_Pop+0x10c>
 8000a50:	b290      	uxth	r0, r2
 8000a52:	1d23      	adds	r3, r4, #4
 8000a54:	f400 5200 	and.w	r2, r0, #8192	@ 0x2000
 8000a58:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8000a5a:	e005      	b.n	8000a68 <_Unwind_VRS_Pop+0x38>
 8000a5c:	07c5      	lsls	r5, r0, #31
 8000a5e:	d001      	beq.n	8000a64 <_Unwind_VRS_Pop+0x34>
 8000a60:	c920      	ldmia	r1!, {r5}
 8000a62:	601d      	str	r5, [r3, #0]
 8000a64:	0840      	lsrs	r0, r0, #1
 8000a66:	1d1b      	adds	r3, r3, #4
 8000a68:	2800      	cmp	r0, #0
 8000a6a:	d1f7      	bne.n	8000a5c <_Unwind_VRS_Pop+0x2c>
 8000a6c:	bbf2      	cbnz	r2, 8000aec <_Unwind_VRS_Pop+0xbc>
 8000a6e:	63a1      	str	r1, [r4, #56]	@ 0x38
 8000a70:	e05e      	b.n	8000b30 <_Unwind_VRS_Pop+0x100>
 8000a72:	0c15      	lsrs	r5, r2, #16
 8000a74:	b296      	uxth	r6, r2
 8000a76:	2d10      	cmp	r5, #16
 8000a78:	d201      	bcs.n	8000a7e <_Unwind_VRS_Pop+0x4e>
 8000a7a:	2001      	movs	r0, #1
 8000a7c:	e000      	b.n	8000a80 <_Unwind_VRS_Pop+0x50>
 8000a7e:	2000      	movs	r0, #0
 8000a80:	4682      	mov	sl, r0
 8000a82:	19a8      	adds	r0, r5, r6
 8000a84:	2810      	cmp	r0, #16
 8000a86:	d901      	bls.n	8000a8c <_Unwind_VRS_Pop+0x5c>
 8000a88:	2701      	movs	r7, #1
 8000a8a:	e000      	b.n	8000a8e <_Unwind_VRS_Pop+0x5e>
 8000a8c:	2700      	movs	r7, #0
 8000a8e:	f1b8 0f01 	cmp.w	r8, #1
 8000a92:	d003      	beq.n	8000a9c <_Unwind_VRS_Pop+0x6c>
 8000a94:	f1b8 0f05 	cmp.w	r8, #5
 8000a98:	d150      	bne.n	8000b3c <_Unwind_VRS_Pop+0x10c>
 8000a9a:	e001      	b.n	8000aa0 <_Unwind_VRS_Pop+0x70>
 8000a9c:	bb3f      	cbnz	r7, 8000aee <_Unwind_VRS_Pop+0xbe>
 8000a9e:	e001      	b.n	8000aa4 <_Unwind_VRS_Pop+0x74>
 8000aa0:	2820      	cmp	r0, #32
 8000aa2:	d84b      	bhi.n	8000b3c <_Unwind_VRS_Pop+0x10c>
 8000aa4:	f04f 0b00 	mov.w	fp, #0
 8000aa8:	f1ba 0f00 	cmp.w	sl, #0
 8000aac:	d008      	beq.n	8000ac0 <_Unwind_VRS_Pop+0x90>
 8000aae:	7820      	ldrb	r0, [r4, #0]
 8000ab0:	2801      	cmp	r0, #1
 8000ab2:	d105      	bne.n	8000ac0 <_Unwind_VRS_Pop+0x90>
 8000ab4:	f884 b000 	strb.w	fp, [r4]
 8000ab8:	f104 0048 	add.w	r0, r4, #72	@ 0x48
 8000abc:	ec80 0b20 	vstmia	r0, {d0-d15}
 8000ac0:	b147      	cbz	r7, 8000ad4 <_Unwind_VRS_Pop+0xa4>
 8000ac2:	7860      	ldrb	r0, [r4, #1]
 8000ac4:	2801      	cmp	r0, #1
 8000ac6:	d105      	bne.n	8000ad4 <_Unwind_VRS_Pop+0xa4>
 8000ac8:	f884 b001 	strb.w	fp, [r4, #1]
 8000acc:	f104 00c8 	add.w	r0, r4, #200	@ 0xc8
 8000ad0:	ecc0 0b20 	vstmia	r0, {d16-d31}
 8000ad4:	f1ba 0f00 	cmp.w	sl, #0
 8000ad8:	d002      	beq.n	8000ae0 <_Unwind_VRS_Pop+0xb0>
 8000ada:	4668      	mov	r0, sp
 8000adc:	ec80 0b20 	vstmia	r0, {d0-d15}
 8000ae0:	a820      	add	r0, sp, #128	@ 0x80
 8000ae2:	4683      	mov	fp, r0
 8000ae4:	b10f      	cbz	r7, 8000aea <_Unwind_VRS_Pop+0xba>
 8000ae6:	ecc0 0b20 	vstmia	r0, {d16-d31}
 8000aea:	e001      	b.n	8000af0 <_Unwind_VRS_Pop+0xc0>
 8000aec:	e020      	b.n	8000b30 <_Unwind_VRS_Pop+0x100>
 8000aee:	e025      	b.n	8000b3c <_Unwind_VRS_Pop+0x10c>
 8000af0:	466b      	mov	r3, sp
 8000af2:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8000af4:	e008      	b.n	8000b08 <_Unwind_VRS_Pop+0xd8>
 8000af6:	4601      	mov	r1, r0
 8000af8:	eb03 02c5 	add.w	r2, r3, r5, lsl #3
 8000afc:	e9d1 c100 	ldrd	ip, r1, [r1]
 8000b00:	e9c2 c100 	strd	ip, r1, [r2]
 8000b04:	3008      	adds	r0, #8
 8000b06:	1c6d      	adds	r5, r5, #1
 8000b08:	1e76      	subs	r6, r6, #1
 8000b0a:	d2f4      	bcs.n	8000af6 <_Unwind_VRS_Pop+0xc6>
 8000b0c:	4641      	mov	r1, r8
 8000b0e:	f1b8 0f01 	cmp.w	r8, #1
 8000b12:	d000      	beq.n	8000b16 <_Unwind_VRS_Pop+0xe6>
 8000b14:	2100      	movs	r1, #0
 8000b16:	eb00 0081 	add.w	r0, r0, r1, lsl #2
 8000b1a:	63a0      	str	r0, [r4, #56]	@ 0x38
 8000b1c:	f1ba 0f00 	cmp.w	sl, #0
 8000b20:	d002      	beq.n	8000b28 <_Unwind_VRS_Pop+0xf8>
 8000b22:	4618      	mov	r0, r3
 8000b24:	ec90 0b20 	vldmia	r0, {d0-d15}
 8000b28:	b117      	cbz	r7, 8000b30 <_Unwind_VRS_Pop+0x100>
 8000b2a:	4658      	mov	r0, fp
 8000b2c:	ecd0 0b20 	vldmia	r0, {d16-d31}
 8000b30:	2000      	movs	r0, #0
 8000b32:	b040      	add	sp, #256	@ 0x100
 8000b34:	e8bd 8df0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, sl, fp, pc}
 8000b38:	2001      	movs	r0, #1
 8000b3a:	e7fa      	b.n	8000b32 <_Unwind_VRS_Pop+0x102>
 8000b3c:	2002      	movs	r0, #2
 8000b3e:	e7f8      	b.n	8000b32 <_Unwind_VRS_Pop+0x102>

08000b40 <_ZN32_INTERNAL_10_unwinder_c_4536541114EIT_comparatorEPKvS1_>:
 8000b40:	b510      	push	{r4, lr}
 8000b42:	6804      	ldr	r4, [r0, #0]
 8000b44:	4890      	ldr	r0, [pc, #576]	@ (8000d88 <_Unwind_Complete+0x48>)
 8000b46:	f101 0208 	add.w	r2, r1, #8
 8000b4a:	6843      	ldr	r3, [r0, #4]
 8000b4c:	4403      	add	r3, r0
 8000b4e:	f04f 30ff 	mov.w	r0, #4294967295
 8000b52:	4293      	cmp	r3, r2
 8000b54:	d004      	beq.n	8000b60 <_ZN32_INTERNAL_10_unwinder_c_4536541114EIT_comparatorEPKvS1_+0x20>
 8000b56:	6813      	ldr	r3, [r2, #0]
 8000b58:	f343 031e 	sbfx	r3, r3, #0, #31
 8000b5c:	4413      	add	r3, r2
 8000b5e:	e000      	b.n	8000b62 <_ZN32_INTERNAL_10_unwinder_c_4536541114EIT_comparatorEPKvS1_+0x22>
 8000b60:	4603      	mov	r3, r0
 8000b62:	680a      	ldr	r2, [r1, #0]
 8000b64:	f342 021e 	sbfx	r2, r2, #0, #31
 8000b68:	4411      	add	r1, r2
 8000b6a:	42a1      	cmp	r1, r4
 8000b6c:	d802      	bhi.n	8000b74 <_ZN32_INTERNAL_10_unwinder_c_4536541114EIT_comparatorEPKvS1_+0x34>
 8000b6e:	429c      	cmp	r4, r3
 8000b70:	d301      	bcc.n	8000b76 <_ZN32_INTERNAL_10_unwinder_c_4536541114EIT_comparatorEPKvS1_+0x36>
 8000b72:	2001      	movs	r0, #1
 8000b74:	bd10      	pop	{r4, pc}
 8000b76:	2000      	movs	r0, #0
 8000b78:	bd10      	pop	{r4, pc}

08000b7a <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj>:
 8000b7a:	b533      	push	{r0, r1, r4, r5, lr}
 8000b7c:	4604      	mov	r4, r0
 8000b7e:	4882      	ldr	r0, [pc, #520]	@ (8000d88 <_Unwind_Complete+0x48>)
 8000b80:	b081      	sub	sp, #4
 8000b82:	4d82      	ldr	r5, [pc, #520]	@ (8000d8c <_Unwind_Complete+0x4c>)
 8000b84:	6801      	ldr	r1, [r0, #0]
 8000b86:	6842      	ldr	r2, [r0, #4]
 8000b88:	4401      	add	r1, r0
 8000b8a:	4410      	add	r0, r2
 8000b8c:	1a40      	subs	r0, r0, r1
 8000b8e:	10c2      	asrs	r2, r0, #3
 8000b90:	9802      	ldr	r0, [sp, #8]
 8000b92:	2308      	movs	r3, #8
 8000b94:	1e80      	subs	r0, r0, #2
 8000b96:	9002      	str	r0, [sp, #8]
 8000b98:	a802      	add	r0, sp, #8
 8000b9a:	9500      	str	r5, [sp, #0]
 8000b9c:	f000 f921 	bl	8000de2 <bsearch>
 8000ba0:	497b      	ldr	r1, [pc, #492]	@ (8000d90 <_Unwind_Complete+0x50>)
 8000ba2:	2300      	movs	r3, #0
 8000ba4:	b170      	cbz	r0, 8000bc4 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x4a>
 8000ba6:	6802      	ldr	r2, [r0, #0]
 8000ba8:	f342 021e 	sbfx	r2, r2, #0, #31
 8000bac:	4402      	add	r2, r0
 8000bae:	64a2      	str	r2, [r4, #72]	@ 0x48
 8000bb0:	6842      	ldr	r2, [r0, #4]
 8000bb2:	2a01      	cmp	r2, #1
 8000bb4:	d009      	beq.n	8000bca <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x50>
 8000bb6:	2a00      	cmp	r2, #0
 8000bb8:	da0a      	bge.n	8000bd0 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x56>
 8000bba:	1d00      	adds	r0, r0, #4
 8000bbc:	64e0      	str	r0, [r4, #76]	@ 0x4c
 8000bbe:	2001      	movs	r0, #1
 8000bc0:	6520      	str	r0, [r4, #80]	@ 0x50
 8000bc2:	e00b      	b.n	8000bdc <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x62>
 8000bc4:	2204      	movs	r2, #4
 8000bc6:	6163      	str	r3, [r4, #20]
 8000bc8:	e015      	b.n	8000bf6 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x7c>
 8000bca:	2202      	movs	r2, #2
 8000bcc:	6163      	str	r3, [r4, #20]
 8000bce:	e012      	b.n	8000bf6 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x7c>
 8000bd0:	f342 021e 	sbfx	r2, r2, #0, #31
 8000bd4:	1d00      	adds	r0, r0, #4
 8000bd6:	4410      	add	r0, r2
 8000bd8:	e9c4 0313 	strd	r0, r3, [r4, #76]	@ 0x4c
 8000bdc:	6ce2      	ldr	r2, [r4, #76]	@ 0x4c
 8000bde:	6810      	ldr	r0, [r2, #0]
 8000be0:	2800      	cmp	r0, #0
 8000be2:	da15      	bge.n	8000c10 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x96>
 8000be4:	f3c0 6003 	ubfx	r0, r0, #24, #4
 8000be8:	b150      	cbz	r0, 8000c00 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x86>
 8000bea:	2801      	cmp	r0, #1
 8000bec:	d00a      	beq.n	8000c04 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x8a>
 8000bee:	2802      	cmp	r0, #2
 8000bf0:	d00c      	beq.n	8000c0c <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x92>
 8000bf2:	2201      	movs	r2, #1
 8000bf4:	6163      	str	r3, [r4, #20]
 8000bf6:	4620      	mov	r0, r4
 8000bf8:	f7ff fae4 	bl	80001c4 <_Unwind_Activity>
 8000bfc:	2009      	movs	r0, #9
 8000bfe:	bd3e      	pop	{r1, r2, r3, r4, r5, pc}
 8000c00:	4864      	ldr	r0, [pc, #400]	@ (8000d94 <_Unwind_Complete+0x54>)
 8000c02:	e000      	b.n	8000c06 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x8c>
 8000c04:	4864      	ldr	r0, [pc, #400]	@ (8000d98 <_Unwind_Complete+0x58>)
 8000c06:	6160      	str	r0, [r4, #20]
 8000c08:	2000      	movs	r0, #0
 8000c0a:	bd3e      	pop	{r1, r2, r3, r4, r5, pc}
 8000c0c:	4863      	ldr	r0, [pc, #396]	@ (8000d9c <_Unwind_Complete+0x5c>)
 8000c0e:	e7fa      	b.n	8000c06 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x8c>
 8000c10:	f340 001e 	sbfx	r0, r0, #0, #31
 8000c14:	4410      	add	r0, r2
 8000c16:	e7f6      	b.n	8000c06 <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj+0x8c>

08000c18 <__ARM_unwind_next_frame>:
 8000c18:	460c      	mov	r4, r1
 8000c1a:	4605      	mov	r5, r0
 8000c1c:	4628      	mov	r0, r5
 8000c1e:	6c21      	ldr	r1, [r4, #64]	@ 0x40
 8000c20:	f7ff ffab 	bl	8000b7a <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj>
 8000c24:	b950      	cbnz	r0, 8000c3c <__ARM_unwind_next_frame+0x24>
 8000c26:	6c20      	ldr	r0, [r4, #64]	@ 0x40
 8000c28:	6128      	str	r0, [r5, #16]
 8000c2a:	696b      	ldr	r3, [r5, #20]
 8000c2c:	4622      	mov	r2, r4
 8000c2e:	4629      	mov	r1, r5
 8000c30:	2001      	movs	r0, #1
 8000c32:	4798      	blx	r3
 8000c34:	2807      	cmp	r0, #7
 8000c36:	d003      	beq.n	8000c40 <__ARM_unwind_next_frame+0x28>
 8000c38:	2808      	cmp	r0, #8
 8000c3a:	d0ef      	beq.n	8000c1c <__ARM_unwind_next_frame+0x4>
 8000c3c:	f3af 8000 	nop.w
 8000c40:	1d20      	adds	r0, r4, #4
 8000c42:	f7ff fa8d 	bl	8000160 <__ARM_Unwind_VRS_corerestore>

08000c46 <__ARM_Unwind_RaiseException>:
 8000c46:	b5f0      	push	{r4, r5, r6, r7, lr}
 8000c48:	4604      	mov	r4, r0
 8000c4a:	68c0      	ldr	r0, [r0, #12]
 8000c4c:	b0d3      	sub	sp, #332	@ 0x14c
 8000c4e:	460e      	mov	r6, r1
 8000c50:	2701      	movs	r7, #1
 8000c52:	b368      	cbz	r0, 8000cb0 <__ARM_Unwind_RaiseException+0x6a>
 8000c54:	2058      	movs	r0, #88	@ 0x58
 8000c56:	f005 fc55 	bl	8006504 <malloc>
 8000c5a:	0005      	movs	r5, r0
 8000c5c:	d02a      	beq.n	8000cb4 <__ARM_Unwind_RaiseException+0x6e>
 8000c5e:	2214      	movs	r2, #20
 8000c60:	f104 010c 	add.w	r1, r4, #12
 8000c64:	f105 000c 	add.w	r0, r5, #12
 8000c68:	f000 f8de 	bl	8000e28 <__aeabi_memcpy>
 8000c6c:	2218      	movs	r2, #24
 8000c6e:	f104 0120 	add.w	r1, r4, #32
 8000c72:	f105 0020 	add.w	r0, r5, #32
 8000c76:	f000 f8d7 	bl	8000e28 <__aeabi_memcpy>
 8000c7a:	f104 0038 	add.w	r0, r4, #56	@ 0x38
 8000c7e:	f105 0c38 	add.w	ip, r5, #56	@ 0x38
 8000c82:	c80f      	ldmia	r0, {r0, r1, r2, r3}
 8000c84:	e88c 000f 	stmia.w	ip, {r0, r1, r2, r3}
 8000c88:	60e5      	str	r5, [r4, #12]
 8000c8a:	6bf0      	ldr	r0, [r6, #60]	@ 0x3c
 8000c8c:	6430      	str	r0, [r6, #64]	@ 0x40
 8000c8e:	2240      	movs	r2, #64	@ 0x40
 8000c90:	1d31      	adds	r1, r6, #4
 8000c92:	a801      	add	r0, sp, #4
 8000c94:	f000 f8c8 	bl	8000e28 <__aeabi_memcpy>
 8000c98:	f88d 7000 	strb.w	r7, [sp]
 8000c9c:	f88d 7001 	strb.w	r7, [sp, #1]
 8000ca0:	af12      	add	r7, sp, #72	@ 0x48
 8000ca2:	ad32      	add	r5, sp, #200	@ 0xc8
 8000ca4:	4620      	mov	r0, r4
 8000ca6:	9910      	ldr	r1, [sp, #64]	@ 0x40
 8000ca8:	f7ff ff67 	bl	8000b7a <_ZN32_INTERNAL_10_unwinder_c_4536541125find_and_expand_eit_entryEP21_Unwind_Control_Blockj>
 8000cac:	b9d0      	cbnz	r0, 8000ce4 <__ARM_Unwind_RaiseException+0x9e>
 8000cae:	e010      	b.n	8000cd2 <__ARM_Unwind_RaiseException+0x8c>
 8000cb0:	60e7      	str	r7, [r4, #12]
 8000cb2:	e7ea      	b.n	8000c8a <__ARM_Unwind_RaiseException+0x44>
 8000cb4:	2205      	movs	r2, #5
 8000cb6:	4936      	ldr	r1, [pc, #216]	@ (8000d90 <_Unwind_Complete+0x50>)
 8000cb8:	4620      	mov	r0, r4
 8000cba:	f7ff fa83 	bl	80001c4 <_Unwind_Activity>
 8000cbe:	e005      	b.n	8000ccc <__ARM_Unwind_RaiseException+0x86>
 8000cc0:	f89d 0001 	ldrb.w	r0, [sp, #1]
 8000cc4:	b910      	cbnz	r0, 8000ccc <__ARM_Unwind_RaiseException+0x86>
 8000cc6:	4628      	mov	r0, r5
 8000cc8:	ecd0 0b20 	vldmia	r0, {d16-d31}
 8000ccc:	b053      	add	sp, #332	@ 0x14c
 8000cce:	2009      	movs	r0, #9
 8000cd0:	bdf0      	pop	{r4, r5, r6, r7, pc}
 8000cd2:	6963      	ldr	r3, [r4, #20]
 8000cd4:	466a      	mov	r2, sp
 8000cd6:	4621      	mov	r1, r4
 8000cd8:	2000      	movs	r0, #0
 8000cda:	4798      	blx	r3
 8000cdc:	2806      	cmp	r0, #6
 8000cde:	d009      	beq.n	8000cf4 <__ARM_Unwind_RaiseException+0xae>
 8000ce0:	2808      	cmp	r0, #8
 8000ce2:	d0df      	beq.n	8000ca4 <__ARM_Unwind_RaiseException+0x5e>
 8000ce4:	f89d 0000 	ldrb.w	r0, [sp]
 8000ce8:	2800      	cmp	r0, #0
 8000cea:	d1e9      	bne.n	8000cc0 <__ARM_Unwind_RaiseException+0x7a>
 8000cec:	4638      	mov	r0, r7
 8000cee:	ec90 0b20 	vldmia	r0, {d0-d15}
 8000cf2:	e7e5      	b.n	8000cc0 <__ARM_Unwind_RaiseException+0x7a>
 8000cf4:	f89d 0000 	ldrb.w	r0, [sp]
 8000cf8:	b910      	cbnz	r0, 8000d00 <__ARM_Unwind_RaiseException+0xba>
 8000cfa:	4638      	mov	r0, r7
 8000cfc:	ec90 0b20 	vldmia	r0, {d0-d15}
 8000d00:	f89d 0001 	ldrb.w	r0, [sp, #1]
 8000d04:	b910      	cbnz	r0, 8000d0c <__ARM_Unwind_RaiseException+0xc6>
 8000d06:	4628      	mov	r0, r5
 8000d08:	ecd0 0b20 	vldmia	r0, {d16-d31}
 8000d0c:	4631      	mov	r1, r6
 8000d0e:	4620      	mov	r0, r4
 8000d10:	f7ff ff82 	bl	8000c18 <__ARM_unwind_next_frame>

08000d14 <__ARM_Unwind_Resume>:
 8000d14:	4605      	mov	r5, r0
 8000d16:	6900      	ldr	r0, [r0, #16]
 8000d18:	6408      	str	r0, [r1, #64]	@ 0x40
 8000d1a:	460c      	mov	r4, r1
 8000d1c:	460a      	mov	r2, r1
 8000d1e:	696b      	ldr	r3, [r5, #20]
 8000d20:	4629      	mov	r1, r5
 8000d22:	2002      	movs	r0, #2
 8000d24:	4798      	blx	r3
 8000d26:	2807      	cmp	r0, #7
 8000d28:	d003      	beq.n	8000d32 <__ARM_Unwind_Resume+0x1e>
 8000d2a:	2808      	cmp	r0, #8
 8000d2c:	d004      	beq.n	8000d38 <__ARM_Unwind_Resume+0x24>
 8000d2e:	f3af 8000 	nop.w
 8000d32:	1d20      	adds	r0, r4, #4
 8000d34:	f7ff fa14 	bl	8000160 <__ARM_Unwind_VRS_corerestore>
 8000d38:	4621      	mov	r1, r4
 8000d3a:	4628      	mov	r0, r5
 8000d3c:	f7ff ff6c 	bl	8000c18 <__ARM_unwind_next_frame>

08000d40 <_Unwind_Complete>:
 8000d40:	b570      	push	{r4, r5, r6, lr}
 8000d42:	68c1      	ldr	r1, [r0, #12]
 8000d44:	4605      	mov	r5, r0
 8000d46:	b1d1      	cbz	r1, 8000d7e <_Unwind_Complete+0x3e>
 8000d48:	2901      	cmp	r1, #1
 8000d4a:	d01a      	beq.n	8000d82 <_Unwind_Complete+0x42>
 8000d4c:	460c      	mov	r4, r1
 8000d4e:	2214      	movs	r2, #20
 8000d50:	f105 000c 	add.w	r0, r5, #12
 8000d54:	310c      	adds	r1, #12
 8000d56:	f000 f867 	bl	8000e28 <__aeabi_memcpy>
 8000d5a:	2218      	movs	r2, #24
 8000d5c:	f104 0120 	add.w	r1, r4, #32
 8000d60:	f105 0020 	add.w	r0, r5, #32
 8000d64:	f000 f860 	bl	8000e28 <__aeabi_memcpy>
 8000d68:	f104 0038 	add.w	r0, r4, #56	@ 0x38
 8000d6c:	3538      	adds	r5, #56	@ 0x38
 8000d6e:	c80f      	ldmia	r0, {r0, r1, r2, r3}
 8000d70:	e885 000f 	stmia.w	r5, {r0, r1, r2, r3}
 8000d74:	4620      	mov	r0, r4
 8000d76:	e8bd 4070 	ldmia.w	sp!, {r4, r5, r6, lr}
 8000d7a:	f005 bb87 	b.w	800648c <free>
 8000d7e:	f3af 8000 	nop.w
 8000d82:	2000      	movs	r0, #0
 8000d84:	60e8      	str	r0, [r5, #12]
 8000d86:	bd70      	pop	{r4, r5, r6, pc}
 8000d88:	080001a0 	.word	0x080001a0
 8000d8c:	08000b41 	.word	0x08000b41
 8000d90:	ff000001 	.word	0xff000001
 8000d94:	08000333 	.word	0x08000333
 8000d98:	0800032d 	.word	0x0800032d
 8000d9c:	00000000 	.word	0x00000000

08000da0 <__scatterload>:
 8000da0:	4c06      	ldr	r4, [pc, #24]	@ (8000dbc <__scatterload+0x1c>)
 8000da2:	4d07      	ldr	r5, [pc, #28]	@ (8000dc0 <__scatterload+0x20>)
 8000da4:	e006      	b.n	8000db4 <__scatterload+0x14>
 8000da6:	68e0      	ldr	r0, [r4, #12]
 8000da8:	f040 0301 	orr.w	r3, r0, #1
 8000dac:	e894 0007 	ldmia.w	r4, {r0, r1, r2}
 8000db0:	4798      	blx	r3
 8000db2:	3410      	adds	r4, #16
 8000db4:	42ac      	cmp	r4, r5
 8000db6:	d3f6      	bcc.n	8000da6 <__scatterload+0x6>
 8000db8:	f7ff f9be 	bl	8000138 <__main_after_scatterload>
 8000dbc:	08006d08 	.word	0x08006d08
 8000dc0:	08006d28 	.word	0x08006d28

08000dc4 <__aeabi_llsl>:
 8000dc4:	2a20      	cmp	r2, #32
 8000dc6:	db04      	blt.n	8000dd2 <__aeabi_llsl+0xe>
 8000dc8:	3a20      	subs	r2, #32
 8000dca:	fa00 f102 	lsl.w	r1, r0, r2
 8000dce:	2000      	movs	r0, #0
 8000dd0:	4770      	bx	lr
 8000dd2:	4091      	lsls	r1, r2
 8000dd4:	f1c2 0320 	rsb	r3, r2, #32
 8000dd8:	fa20 f303 	lsr.w	r3, r0, r3
 8000ddc:	4319      	orrs	r1, r3
 8000dde:	4090      	lsls	r0, r2
 8000de0:	4770      	bx	lr

08000de2 <bsearch>:
 8000de2:	e92d 5ff0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, ip, lr}
 8000de6:	4699      	mov	r9, r3
 8000de8:	4615      	mov	r5, r2
 8000dea:	460f      	mov	r7, r1
 8000dec:	4683      	mov	fp, r0
 8000dee:	f04f 36ff 	mov.w	r6, #4294967295
 8000df2:	f8dd a028 	ldr.w	sl, [sp, #40]	@ 0x28
 8000df6:	e011      	b.n	8000e1c <bsearch+0x3a>
 8000df8:	19a8      	adds	r0, r5, r6
 8000dfa:	1044      	asrs	r4, r0, #1
 8000dfc:	fb09 7004 	mla	r0, r9, r4, r7
 8000e00:	4680      	mov	r8, r0
 8000e02:	4601      	mov	r1, r0
 8000e04:	4658      	mov	r0, fp
 8000e06:	4652      	mov	r2, sl
 8000e08:	4790      	blx	r2
 8000e0a:	2800      	cmp	r0, #0
 8000e0c:	d002      	beq.n	8000e14 <bsearch+0x32>
 8000e0e:	da04      	bge.n	8000e1a <bsearch+0x38>
 8000e10:	4625      	mov	r5, r4
 8000e12:	e003      	b.n	8000e1c <bsearch+0x3a>
 8000e14:	4640      	mov	r0, r8
 8000e16:	e8bd 9ff0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, ip, pc}
 8000e1a:	4626      	mov	r6, r4
 8000e1c:	eba5 0006 	sub.w	r0, r5, r6
 8000e20:	2801      	cmp	r0, #1
 8000e22:	dce9      	bgt.n	8000df8 <bsearch+0x16>
 8000e24:	2000      	movs	r0, #0
 8000e26:	e7f6      	b.n	8000e16 <bsearch+0x34>

08000e28 <__aeabi_memcpy>:
 8000e28:	ea40 0301 	orr.w	r3, r0, r1
 8000e2c:	079b      	lsls	r3, r3, #30
 8000e2e:	d003      	beq.n	8000e38 <__aeabi_memcpy+0x10>
 8000e30:	e009      	b.n	8000e46 <__aeabi_memcpy+0x1e>
 8000e32:	c908      	ldmia	r1!, {r3}
 8000e34:	1f12      	subs	r2, r2, #4
 8000e36:	c008      	stmia	r0!, {r3}
 8000e38:	2a04      	cmp	r2, #4
 8000e3a:	d2fa      	bcs.n	8000e32 <__aeabi_memcpy+0xa>
 8000e3c:	e003      	b.n	8000e46 <__aeabi_memcpy+0x1e>
 8000e3e:	f811 3b01 	ldrb.w	r3, [r1], #1
 8000e42:	f800 3b01 	strb.w	r3, [r0], #1
 8000e46:	1e52      	subs	r2, r2, #1
 8000e48:	d2f9      	bcs.n	8000e3e <__aeabi_memcpy+0x16>
 8000e4a:	4770      	bx	lr

08000e4c <BusFault_Handler>:
 8000e4c:	bf00      	nop
 8000e4e:	e7fe      	b.n	8000e4e <BusFault_Handler+0x2>

08000e50 <DMA_SetConfig>:
 8000e50:	b530      	push	{r4, r5, lr}
 8000e52:	f890 5040 	ldrb.w	r5, [r0, #64]	@ 0x40
 8000e56:	2401      	movs	r4, #1
 8000e58:	40ac      	lsls	r4, r5
 8000e5a:	6bc5      	ldr	r5, [r0, #60]	@ 0x3c
 8000e5c:	606c      	str	r4, [r5, #4]
 8000e5e:	6804      	ldr	r4, [r0, #0]
 8000e60:	6063      	str	r3, [r4, #4]
 8000e62:	6844      	ldr	r4, [r0, #4]
 8000e64:	2c10      	cmp	r4, #16
 8000e66:	d104      	bne.n	8000e72 <DMA_SetConfig+0x22>
 8000e68:	6804      	ldr	r4, [r0, #0]
 8000e6a:	60a2      	str	r2, [r4, #8]
 8000e6c:	6804      	ldr	r4, [r0, #0]
 8000e6e:	60e1      	str	r1, [r4, #12]
 8000e70:	e003      	b.n	8000e7a <DMA_SetConfig+0x2a>
 8000e72:	6804      	ldr	r4, [r0, #0]
 8000e74:	60a1      	str	r1, [r4, #8]
 8000e76:	6804      	ldr	r4, [r0, #0]
 8000e78:	60e2      	str	r2, [r4, #12]
 8000e7a:	bd30      	pop	{r4, r5, pc}

08000e7c <DebugMon_Handler>:
 8000e7c:	4770      	bx	lr

08000e7e <Error_Handler>:
 8000e7e:	b672      	cpsid	i
 8000e80:	bf00      	nop
 8000e82:	e7fe      	b.n	8000e82 <Error_Handler+0x4>

08000e84 <FLASH_MassErase>:
 8000e84:	2100      	movs	r1, #0
 8000e86:	4a07      	ldr	r2, [pc, #28]	@ (8000ea4 <FLASH_MassErase+0x20>)
 8000e88:	61d1      	str	r1, [r2, #28]
 8000e8a:	4907      	ldr	r1, [pc, #28]	@ (8000ea8 <FLASH_MassErase+0x24>)
 8000e8c:	6909      	ldr	r1, [r1, #16]
 8000e8e:	f041 0104 	orr.w	r1, r1, #4
 8000e92:	4a05      	ldr	r2, [pc, #20]	@ (8000ea8 <FLASH_MassErase+0x24>)
 8000e94:	6111      	str	r1, [r2, #16]
 8000e96:	4611      	mov	r1, r2
 8000e98:	6909      	ldr	r1, [r1, #16]
 8000e9a:	f041 0140 	orr.w	r1, r1, #64	@ 0x40
 8000e9e:	6111      	str	r1, [r2, #16]
 8000ea0:	4770      	bx	lr
 8000ea2:	0000      	.short	0x0000
 8000ea4:	20000070 	.word	0x20000070
 8000ea8:	40022000 	.word	0x40022000

08000eac <FLASH_OB_DisableWRP>:
 8000eac:	e92d 47f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, lr}
 8000eb0:	4604      	mov	r4, r0
 8000eb2:	2500      	movs	r5, #0
 8000eb4:	f64f 76ff 	movw	r6, #65535	@ 0xffff
 8000eb8:	4637      	mov	r7, r6
 8000eba:	46b0      	mov	r8, r6
 8000ebc:	46b1      	mov	r9, r6
 8000ebe:	f000 f8f5 	bl	80010ac <FLASH_OB_GetWRP>
 8000ec2:	4304      	orrs	r4, r0
 8000ec4:	b2e6      	uxtb	r6, r4
 8000ec6:	f3c4 2707 	ubfx	r7, r4, #8, #8
 8000eca:	f3c4 4807 	ubfx	r8, r4, #16, #8
 8000ece:	ea4f 6914 	mov.w	r9, r4, lsr #24
 8000ed2:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8000ed6:	f000 f9e3 	bl	80012a0 <FLASH_WaitForLastOperation>
 8000eda:	4605      	mov	r5, r0
 8000edc:	2d00      	cmp	r5, #0
 8000ede:	d14f      	bne.n	8000f80 <FLASH_OB_DisableWRP+0xd4>
 8000ee0:	4929      	ldr	r1, [pc, #164]	@ (8000f88 <FLASH_OB_DisableWRP+0xdc>)
 8000ee2:	61c8      	str	r0, [r1, #28]
 8000ee4:	f001 fbc0 	bl	8002668 <HAL_FLASHEx_OBErase>
 8000ee8:	4605      	mov	r5, r0
 8000eea:	2d00      	cmp	r5, #0
 8000eec:	d148      	bne.n	8000f80 <FLASH_OB_DisableWRP+0xd4>
 8000eee:	4827      	ldr	r0, [pc, #156]	@ (8000f8c <FLASH_OB_DisableWRP+0xe0>)
 8000ef0:	6900      	ldr	r0, [r0, #16]
 8000ef2:	f040 0010 	orr.w	r0, r0, #16
 8000ef6:	4925      	ldr	r1, [pc, #148]	@ (8000f8c <FLASH_OB_DisableWRP+0xe0>)
 8000ef8:	6108      	str	r0, [r1, #16]
 8000efa:	2eff      	cmp	r6, #255	@ 0xff
 8000efc:	d009      	beq.n	8000f12 <FLASH_OB_DisableWRP+0x66>
 8000efe:	4824      	ldr	r0, [pc, #144]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f00:	8800      	ldrh	r0, [r0, #0]
 8000f02:	4330      	orrs	r0, r6
 8000f04:	4922      	ldr	r1, [pc, #136]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f06:	8008      	strh	r0, [r1, #0]
 8000f08:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8000f0c:	f000 f9c8 	bl	80012a0 <FLASH_WaitForLastOperation>
 8000f10:	4605      	mov	r5, r0
 8000f12:	b96d      	cbnz	r5, 8000f30 <FLASH_OB_DisableWRP+0x84>
 8000f14:	2fff      	cmp	r7, #255	@ 0xff
 8000f16:	d00b      	beq.n	8000f30 <FLASH_OB_DisableWRP+0x84>
 8000f18:	481d      	ldr	r0, [pc, #116]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f1a:	1c80      	adds	r0, r0, #2
 8000f1c:	8800      	ldrh	r0, [r0, #0]
 8000f1e:	4338      	orrs	r0, r7
 8000f20:	491b      	ldr	r1, [pc, #108]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f22:	1c89      	adds	r1, r1, #2
 8000f24:	8008      	strh	r0, [r1, #0]
 8000f26:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8000f2a:	f000 f9b9 	bl	80012a0 <FLASH_WaitForLastOperation>
 8000f2e:	4605      	mov	r5, r0
 8000f30:	b97d      	cbnz	r5, 8000f52 <FLASH_OB_DisableWRP+0xa6>
 8000f32:	f1b8 0fff 	cmp.w	r8, #255	@ 0xff
 8000f36:	d00c      	beq.n	8000f52 <FLASH_OB_DisableWRP+0xa6>
 8000f38:	4815      	ldr	r0, [pc, #84]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f3a:	1d00      	adds	r0, r0, #4
 8000f3c:	8800      	ldrh	r0, [r0, #0]
 8000f3e:	ea40 0008 	orr.w	r0, r0, r8
 8000f42:	4913      	ldr	r1, [pc, #76]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f44:	1d09      	adds	r1, r1, #4
 8000f46:	8008      	strh	r0, [r1, #0]
 8000f48:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8000f4c:	f000 f9a8 	bl	80012a0 <FLASH_WaitForLastOperation>
 8000f50:	4605      	mov	r5, r0
 8000f52:	b97d      	cbnz	r5, 8000f74 <FLASH_OB_DisableWRP+0xc8>
 8000f54:	f1b9 0fff 	cmp.w	r9, #255	@ 0xff
 8000f58:	d00c      	beq.n	8000f74 <FLASH_OB_DisableWRP+0xc8>
 8000f5a:	480d      	ldr	r0, [pc, #52]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f5c:	1d80      	adds	r0, r0, #6
 8000f5e:	8800      	ldrh	r0, [r0, #0]
 8000f60:	ea40 0009 	orr.w	r0, r0, r9
 8000f64:	490a      	ldr	r1, [pc, #40]	@ (8000f90 <FLASH_OB_DisableWRP+0xe4>)
 8000f66:	1d89      	adds	r1, r1, #6
 8000f68:	8008      	strh	r0, [r1, #0]
 8000f6a:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8000f6e:	f000 f997 	bl	80012a0 <FLASH_WaitForLastOperation>
 8000f72:	4605      	mov	r5, r0
 8000f74:	4805      	ldr	r0, [pc, #20]	@ (8000f8c <FLASH_OB_DisableWRP+0xe0>)
 8000f76:	6900      	ldr	r0, [r0, #16]
 8000f78:	f020 0010 	bic.w	r0, r0, #16
 8000f7c:	4903      	ldr	r1, [pc, #12]	@ (8000f8c <FLASH_OB_DisableWRP+0xe0>)
 8000f7e:	6108      	str	r0, [r1, #16]
 8000f80:	4628      	mov	r0, r5
 8000f82:	e8bd 87f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, pc}
 8000f86:	0000      	.short	0x0000
 8000f88:	20000070 	.word	0x20000070
 8000f8c:	40022000 	.word	0x40022000
 8000f90:	1ffff808 	.word	0x1ffff808

08000f94 <FLASH_OB_EnableWRP>:
 8000f94:	e92d 47f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, lr}
 8000f98:	4604      	mov	r4, r0
 8000f9a:	2500      	movs	r5, #0
 8000f9c:	f64f 76ff 	movw	r6, #65535	@ 0xffff
 8000fa0:	4637      	mov	r7, r6
 8000fa2:	46b0      	mov	r8, r6
 8000fa4:	46b1      	mov	r9, r6
 8000fa6:	f000 f881 	bl	80010ac <FLASH_OB_GetWRP>
 8000faa:	43c0      	mvns	r0, r0
 8000fac:	4320      	orrs	r0, r4
 8000fae:	43c4      	mvns	r4, r0
 8000fb0:	b2e6      	uxtb	r6, r4
 8000fb2:	f3c4 2707 	ubfx	r7, r4, #8, #8
 8000fb6:	f3c4 4807 	ubfx	r8, r4, #16, #8
 8000fba:	ea4f 6914 	mov.w	r9, r4, lsr #24
 8000fbe:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8000fc2:	f000 f96d 	bl	80012a0 <FLASH_WaitForLastOperation>
 8000fc6:	4605      	mov	r5, r0
 8000fc8:	2d00      	cmp	r5, #0
 8000fca:	d14f      	bne.n	800106c <FLASH_OB_EnableWRP+0xd8>
 8000fcc:	4929      	ldr	r1, [pc, #164]	@ (8001074 <FLASH_OB_EnableWRP+0xe0>)
 8000fce:	61c8      	str	r0, [r1, #28]
 8000fd0:	f001 fb4a 	bl	8002668 <HAL_FLASHEx_OBErase>
 8000fd4:	4605      	mov	r5, r0
 8000fd6:	2d00      	cmp	r5, #0
 8000fd8:	d148      	bne.n	800106c <FLASH_OB_EnableWRP+0xd8>
 8000fda:	4827      	ldr	r0, [pc, #156]	@ (8001078 <FLASH_OB_EnableWRP+0xe4>)
 8000fdc:	6900      	ldr	r0, [r0, #16]
 8000fde:	f040 0010 	orr.w	r0, r0, #16
 8000fe2:	4925      	ldr	r1, [pc, #148]	@ (8001078 <FLASH_OB_EnableWRP+0xe4>)
 8000fe4:	6108      	str	r0, [r1, #16]
 8000fe6:	2eff      	cmp	r6, #255	@ 0xff
 8000fe8:	d009      	beq.n	8000ffe <FLASH_OB_EnableWRP+0x6a>
 8000fea:	4824      	ldr	r0, [pc, #144]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 8000fec:	8800      	ldrh	r0, [r0, #0]
 8000fee:	4030      	ands	r0, r6
 8000ff0:	4922      	ldr	r1, [pc, #136]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 8000ff2:	8008      	strh	r0, [r1, #0]
 8000ff4:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8000ff8:	f000 f952 	bl	80012a0 <FLASH_WaitForLastOperation>
 8000ffc:	4605      	mov	r5, r0
 8000ffe:	b96d      	cbnz	r5, 800101c <FLASH_OB_EnableWRP+0x88>
 8001000:	2fff      	cmp	r7, #255	@ 0xff
 8001002:	d00b      	beq.n	800101c <FLASH_OB_EnableWRP+0x88>
 8001004:	481d      	ldr	r0, [pc, #116]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 8001006:	1c80      	adds	r0, r0, #2
 8001008:	8800      	ldrh	r0, [r0, #0]
 800100a:	4038      	ands	r0, r7
 800100c:	491b      	ldr	r1, [pc, #108]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 800100e:	1c89      	adds	r1, r1, #2
 8001010:	8008      	strh	r0, [r1, #0]
 8001012:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8001016:	f000 f943 	bl	80012a0 <FLASH_WaitForLastOperation>
 800101a:	4605      	mov	r5, r0
 800101c:	b97d      	cbnz	r5, 800103e <FLASH_OB_EnableWRP+0xaa>
 800101e:	f1b8 0fff 	cmp.w	r8, #255	@ 0xff
 8001022:	d00c      	beq.n	800103e <FLASH_OB_EnableWRP+0xaa>
 8001024:	4815      	ldr	r0, [pc, #84]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 8001026:	1d00      	adds	r0, r0, #4
 8001028:	8800      	ldrh	r0, [r0, #0]
 800102a:	ea00 0008 	and.w	r0, r0, r8
 800102e:	4913      	ldr	r1, [pc, #76]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 8001030:	1d09      	adds	r1, r1, #4
 8001032:	8008      	strh	r0, [r1, #0]
 8001034:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8001038:	f000 f932 	bl	80012a0 <FLASH_WaitForLastOperation>
 800103c:	4605      	mov	r5, r0
 800103e:	b97d      	cbnz	r5, 8001060 <FLASH_OB_EnableWRP+0xcc>
 8001040:	f1b9 0fff 	cmp.w	r9, #255	@ 0xff
 8001044:	d00c      	beq.n	8001060 <FLASH_OB_EnableWRP+0xcc>
 8001046:	480d      	ldr	r0, [pc, #52]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 8001048:	1d80      	adds	r0, r0, #6
 800104a:	8800      	ldrh	r0, [r0, #0]
 800104c:	ea00 0009 	and.w	r0, r0, r9
 8001050:	490a      	ldr	r1, [pc, #40]	@ (800107c <FLASH_OB_EnableWRP+0xe8>)
 8001052:	1d89      	adds	r1, r1, #6
 8001054:	8008      	strh	r0, [r1, #0]
 8001056:	f24c 3050 	movw	r0, #50000	@ 0xc350
 800105a:	f000 f921 	bl	80012a0 <FLASH_WaitForLastOperation>
 800105e:	4605      	mov	r5, r0
 8001060:	4805      	ldr	r0, [pc, #20]	@ (8001078 <FLASH_OB_EnableWRP+0xe4>)
 8001062:	6900      	ldr	r0, [r0, #16]
 8001064:	f020 0010 	bic.w	r0, r0, #16
 8001068:	4903      	ldr	r1, [pc, #12]	@ (8001078 <FLASH_OB_EnableWRP+0xe4>)
 800106a:	6108      	str	r0, [r1, #16]
 800106c:	4628      	mov	r0, r5
 800106e:	e8bd 87f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, pc}
 8001072:	0000      	.short	0x0000
 8001074:	20000070 	.word	0x20000070
 8001078:	40022000 	.word	0x40022000
 800107c:	1ffff808 	.word	0x1ffff808

08001080 <FLASH_OB_GetRDP>:
 8001080:	20a5      	movs	r0, #165	@ 0xa5
 8001082:	2100      	movs	r1, #0
 8001084:	4a04      	ldr	r2, [pc, #16]	@ (8001098 <FLASH_OB_GetRDP+0x18>)
 8001086:	69d2      	ldr	r2, [r2, #28]
 8001088:	f002 0102 	and.w	r1, r2, #2
 800108c:	2902      	cmp	r1, #2
 800108e:	d101      	bne.n	8001094 <FLASH_OB_GetRDP+0x14>
 8001090:	2000      	movs	r0, #0
 8001092:	e000      	b.n	8001096 <FLASH_OB_GetRDP+0x16>
 8001094:	20a5      	movs	r0, #165	@ 0xa5
 8001096:	4770      	bx	lr
 8001098:	40022000 	.word	0x40022000

0800109c <FLASH_OB_GetUser>:
 800109c:	4802      	ldr	r0, [pc, #8]	@ (80010a8 <FLASH_OB_GetUser+0xc>)
 800109e:	69c0      	ldr	r0, [r0, #28]
 80010a0:	f3c0 0082 	ubfx	r0, r0, #2, #3
 80010a4:	4770      	bx	lr
 80010a6:	0000      	.short	0x0000
 80010a8:	40022000 	.word	0x40022000

080010ac <FLASH_OB_GetWRP>:
 80010ac:	4801      	ldr	r0, [pc, #4]	@ (80010b4 <FLASH_OB_GetWRP+0x8>)
 80010ae:	6a00      	ldr	r0, [r0, #32]
 80010b0:	4770      	bx	lr
 80010b2:	0000      	.short	0x0000
 80010b4:	40022000 	.word	0x40022000

080010b8 <FLASH_OB_ProgramData>:
 80010b8:	b570      	push	{r4, r5, r6, lr}
 80010ba:	4604      	mov	r4, r0
 80010bc:	460d      	mov	r5, r1
 80010be:	2601      	movs	r6, #1
 80010c0:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80010c4:	f000 f8ec 	bl	80012a0 <FLASH_WaitForLastOperation>
 80010c8:	4606      	mov	r6, r0
 80010ca:	b9a6      	cbnz	r6, 80010f6 <FLASH_OB_ProgramData+0x3e>
 80010cc:	2000      	movs	r0, #0
 80010ce:	490b      	ldr	r1, [pc, #44]	@ (80010fc <FLASH_OB_ProgramData+0x44>)
 80010d0:	61c8      	str	r0, [r1, #28]
 80010d2:	480b      	ldr	r0, [pc, #44]	@ (8001100 <FLASH_OB_ProgramData+0x48>)
 80010d4:	6900      	ldr	r0, [r0, #16]
 80010d6:	f040 0010 	orr.w	r0, r0, #16
 80010da:	4909      	ldr	r1, [pc, #36]	@ (8001100 <FLASH_OB_ProgramData+0x48>)
 80010dc:	6108      	str	r0, [r1, #16]
 80010de:	8025      	strh	r5, [r4, #0]
 80010e0:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80010e4:	f000 f8dc 	bl	80012a0 <FLASH_WaitForLastOperation>
 80010e8:	4606      	mov	r6, r0
 80010ea:	4805      	ldr	r0, [pc, #20]	@ (8001100 <FLASH_OB_ProgramData+0x48>)
 80010ec:	6900      	ldr	r0, [r0, #16]
 80010ee:	f020 0010 	bic.w	r0, r0, #16
 80010f2:	4903      	ldr	r1, [pc, #12]	@ (8001100 <FLASH_OB_ProgramData+0x48>)
 80010f4:	6108      	str	r0, [r1, #16]
 80010f6:	4630      	mov	r0, r6
 80010f8:	bd70      	pop	{r4, r5, r6, pc}
 80010fa:	0000      	.short	0x0000
 80010fc:	20000070 	.word	0x20000070
 8001100:	40022000 	.word	0x40022000

08001104 <FLASH_OB_RDP_LevelConfig>:
 8001104:	b570      	push	{r4, r5, r6, lr}
 8001106:	4605      	mov	r5, r0
 8001108:	2400      	movs	r4, #0
 800110a:	f24c 3050 	movw	r0, #50000	@ 0xc350
 800110e:	f000 f8c7 	bl	80012a0 <FLASH_WaitForLastOperation>
 8001112:	4604      	mov	r4, r0
 8001114:	bb5c      	cbnz	r4, 800116e <FLASH_OB_RDP_LevelConfig+0x6a>
 8001116:	2000      	movs	r0, #0
 8001118:	4916      	ldr	r1, [pc, #88]	@ (8001174 <FLASH_OB_RDP_LevelConfig+0x70>)
 800111a:	61c8      	str	r0, [r1, #28]
 800111c:	4816      	ldr	r0, [pc, #88]	@ (8001178 <FLASH_OB_RDP_LevelConfig+0x74>)
 800111e:	6900      	ldr	r0, [r0, #16]
 8001120:	f040 0020 	orr.w	r0, r0, #32
 8001124:	4914      	ldr	r1, [pc, #80]	@ (8001178 <FLASH_OB_RDP_LevelConfig+0x74>)
 8001126:	6108      	str	r0, [r1, #16]
 8001128:	4608      	mov	r0, r1
 800112a:	6900      	ldr	r0, [r0, #16]
 800112c:	f040 0040 	orr.w	r0, r0, #64	@ 0x40
 8001130:	6108      	str	r0, [r1, #16]
 8001132:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8001136:	f000 f8b3 	bl	80012a0 <FLASH_WaitForLastOperation>
 800113a:	4604      	mov	r4, r0
 800113c:	480e      	ldr	r0, [pc, #56]	@ (8001178 <FLASH_OB_RDP_LevelConfig+0x74>)
 800113e:	6900      	ldr	r0, [r0, #16]
 8001140:	f020 0020 	bic.w	r0, r0, #32
 8001144:	490c      	ldr	r1, [pc, #48]	@ (8001178 <FLASH_OB_RDP_LevelConfig+0x74>)
 8001146:	6108      	str	r0, [r1, #16]
 8001148:	b98c      	cbnz	r4, 800116e <FLASH_OB_RDP_LevelConfig+0x6a>
 800114a:	4608      	mov	r0, r1
 800114c:	6900      	ldr	r0, [r0, #16]
 800114e:	f040 0010 	orr.w	r0, r0, #16
 8001152:	6108      	str	r0, [r1, #16]
 8001154:	4809      	ldr	r0, [pc, #36]	@ (800117c <FLASH_OB_RDP_LevelConfig+0x78>)
 8001156:	8005      	strh	r5, [r0, #0]
 8001158:	f24c 3050 	movw	r0, #50000	@ 0xc350
 800115c:	f000 f8a0 	bl	80012a0 <FLASH_WaitForLastOperation>
 8001160:	4604      	mov	r4, r0
 8001162:	4805      	ldr	r0, [pc, #20]	@ (8001178 <FLASH_OB_RDP_LevelConfig+0x74>)
 8001164:	6900      	ldr	r0, [r0, #16]
 8001166:	f020 0010 	bic.w	r0, r0, #16
 800116a:	4903      	ldr	r1, [pc, #12]	@ (8001178 <FLASH_OB_RDP_LevelConfig+0x74>)
 800116c:	6108      	str	r0, [r1, #16]
 800116e:	4620      	mov	r0, r4
 8001170:	bd70      	pop	{r4, r5, r6, pc}
 8001172:	0000      	.short	0x0000
 8001174:	20000070 	.word	0x20000070
 8001178:	40022000 	.word	0x40022000
 800117c:	1ffff800 	.word	0x1ffff800

08001180 <FLASH_OB_UserConfig>:
 8001180:	b570      	push	{r4, r5, r6, lr}
 8001182:	4604      	mov	r4, r0
 8001184:	2500      	movs	r5, #0
 8001186:	f24c 3050 	movw	r0, #50000	@ 0xc350
 800118a:	f000 f889 	bl	80012a0 <FLASH_WaitForLastOperation>
 800118e:	4605      	mov	r5, r0
 8001190:	b9bd      	cbnz	r5, 80011c2 <FLASH_OB_UserConfig+0x42>
 8001192:	2000      	movs	r0, #0
 8001194:	490c      	ldr	r1, [pc, #48]	@ (80011c8 <FLASH_OB_UserConfig+0x48>)
 8001196:	61c8      	str	r0, [r1, #28]
 8001198:	480c      	ldr	r0, [pc, #48]	@ (80011cc <FLASH_OB_UserConfig+0x4c>)
 800119a:	6900      	ldr	r0, [r0, #16]
 800119c:	f040 0010 	orr.w	r0, r0, #16
 80011a0:	490a      	ldr	r1, [pc, #40]	@ (80011cc <FLASH_OB_UserConfig+0x4c>)
 80011a2:	6108      	str	r0, [r1, #16]
 80011a4:	f044 0088 	orr.w	r0, r4, #136	@ 0x88
 80011a8:	4909      	ldr	r1, [pc, #36]	@ (80011d0 <FLASH_OB_UserConfig+0x50>)
 80011aa:	8008      	strh	r0, [r1, #0]
 80011ac:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80011b0:	f000 f876 	bl	80012a0 <FLASH_WaitForLastOperation>
 80011b4:	4605      	mov	r5, r0
 80011b6:	4805      	ldr	r0, [pc, #20]	@ (80011cc <FLASH_OB_UserConfig+0x4c>)
 80011b8:	6900      	ldr	r0, [r0, #16]
 80011ba:	f020 0010 	bic.w	r0, r0, #16
 80011be:	4903      	ldr	r1, [pc, #12]	@ (80011cc <FLASH_OB_UserConfig+0x4c>)
 80011c0:	6108      	str	r0, [r1, #16]
 80011c2:	4628      	mov	r0, r5
 80011c4:	bd70      	pop	{r4, r5, r6, pc}
 80011c6:	0000      	.short	0x0000
 80011c8:	20000070 	.word	0x20000070
 80011cc:	40022000 	.word	0x40022000
 80011d0:	1ffff802 	.word	0x1ffff802

080011d4 <FLASH_PageErase>:
 80011d4:	2100      	movs	r1, #0
 80011d6:	4a07      	ldr	r2, [pc, #28]	@ (80011f4 <FLASH_PageErase+0x20>)
 80011d8:	61d1      	str	r1, [r2, #28]
 80011da:	4907      	ldr	r1, [pc, #28]	@ (80011f8 <FLASH_PageErase+0x24>)
 80011dc:	6909      	ldr	r1, [r1, #16]
 80011de:	f041 0102 	orr.w	r1, r1, #2
 80011e2:	4a05      	ldr	r2, [pc, #20]	@ (80011f8 <FLASH_PageErase+0x24>)
 80011e4:	6111      	str	r1, [r2, #16]
 80011e6:	4611      	mov	r1, r2
 80011e8:	6148      	str	r0, [r1, #20]
 80011ea:	6909      	ldr	r1, [r1, #16]
 80011ec:	f041 0140 	orr.w	r1, r1, #64	@ 0x40
 80011f0:	6111      	str	r1, [r2, #16]
 80011f2:	4770      	bx	lr
 80011f4:	20000070 	.word	0x20000070
 80011f8:	40022000 	.word	0x40022000

080011fc <FLASH_Program_HalfWord>:
 80011fc:	2200      	movs	r2, #0
 80011fe:	4b05      	ldr	r3, [pc, #20]	@ (8001214 <FLASH_Program_HalfWord+0x18>)
 8001200:	61da      	str	r2, [r3, #28]
 8001202:	4a05      	ldr	r2, [pc, #20]	@ (8001218 <FLASH_Program_HalfWord+0x1c>)
 8001204:	6912      	ldr	r2, [r2, #16]
 8001206:	f042 0201 	orr.w	r2, r2, #1
 800120a:	4b03      	ldr	r3, [pc, #12]	@ (8001218 <FLASH_Program_HalfWord+0x1c>)
 800120c:	611a      	str	r2, [r3, #16]
 800120e:	8001      	strh	r1, [r0, #0]
 8001210:	4770      	bx	lr
 8001212:	0000      	.short	0x0000
 8001214:	20000070 	.word	0x20000070
 8001218:	40022000 	.word	0x40022000

0800121c <FLASH_SetErrorCode>:
 800121c:	2000      	movs	r0, #0
 800121e:	491e      	ldr	r1, [pc, #120]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 8001220:	68c9      	ldr	r1, [r1, #12]
 8001222:	f001 0110 	and.w	r1, r1, #16
 8001226:	b139      	cbz	r1, 8001238 <FLASH_SetErrorCode+0x1c>
 8001228:	491c      	ldr	r1, [pc, #112]	@ (800129c <FLASH_SetErrorCode+0x80>)
 800122a:	69c9      	ldr	r1, [r1, #28]
 800122c:	f041 0102 	orr.w	r1, r1, #2
 8001230:	4a1a      	ldr	r2, [pc, #104]	@ (800129c <FLASH_SetErrorCode+0x80>)
 8001232:	61d1      	str	r1, [r2, #28]
 8001234:	f040 0010 	orr.w	r0, r0, #16
 8001238:	4917      	ldr	r1, [pc, #92]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 800123a:	68c9      	ldr	r1, [r1, #12]
 800123c:	f001 0104 	and.w	r1, r1, #4
 8001240:	b139      	cbz	r1, 8001252 <FLASH_SetErrorCode+0x36>
 8001242:	4916      	ldr	r1, [pc, #88]	@ (800129c <FLASH_SetErrorCode+0x80>)
 8001244:	69c9      	ldr	r1, [r1, #28]
 8001246:	f041 0101 	orr.w	r1, r1, #1
 800124a:	4a14      	ldr	r2, [pc, #80]	@ (800129c <FLASH_SetErrorCode+0x80>)
 800124c:	61d1      	str	r1, [r2, #28]
 800124e:	f040 0004 	orr.w	r0, r0, #4
 8001252:	4911      	ldr	r1, [pc, #68]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 8001254:	69c9      	ldr	r1, [r1, #28]
 8001256:	f001 0101 	and.w	r1, r1, #1
 800125a:	b169      	cbz	r1, 8001278 <FLASH_SetErrorCode+0x5c>
 800125c:	490f      	ldr	r1, [pc, #60]	@ (800129c <FLASH_SetErrorCode+0x80>)
 800125e:	69c9      	ldr	r1, [r1, #28]
 8001260:	f041 0104 	orr.w	r1, r1, #4
 8001264:	4a0d      	ldr	r2, [pc, #52]	@ (800129c <FLASH_SetErrorCode+0x80>)
 8001266:	61d1      	str	r1, [r2, #28]
 8001268:	bf00      	nop
 800126a:	490b      	ldr	r1, [pc, #44]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 800126c:	69c9      	ldr	r1, [r1, #28]
 800126e:	f021 0101 	bic.w	r1, r1, #1
 8001272:	4a09      	ldr	r2, [pc, #36]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 8001274:	61d1      	str	r1, [r2, #28]
 8001276:	bf00      	nop
 8001278:	bf00      	nop
 800127a:	f240 1101 	movw	r1, #257	@ 0x101
 800127e:	4288      	cmp	r0, r1
 8001280:	d106      	bne.n	8001290 <FLASH_SetErrorCode+0x74>
 8001282:	4905      	ldr	r1, [pc, #20]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 8001284:	69c9      	ldr	r1, [r1, #28]
 8001286:	f021 0101 	bic.w	r1, r1, #1
 800128a:	4a03      	ldr	r2, [pc, #12]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 800128c:	61d1      	str	r1, [r2, #28]
 800128e:	e001      	b.n	8001294 <FLASH_SetErrorCode+0x78>
 8001290:	4901      	ldr	r1, [pc, #4]	@ (8001298 <FLASH_SetErrorCode+0x7c>)
 8001292:	60c8      	str	r0, [r1, #12]
 8001294:	bf00      	nop
 8001296:	4770      	bx	lr
 8001298:	40022000 	.word	0x40022000
 800129c:	20000070 	.word	0x20000070

080012a0 <FLASH_WaitForLastOperation>:
 80012a0:	b570      	push	{r4, r5, r6, lr}
 80012a2:	4604      	mov	r4, r0
 80012a4:	f001 fee8 	bl	8003078 <HAL_GetTick>
 80012a8:	4605      	mov	r5, r0
 80012aa:	e009      	b.n	80012c0 <FLASH_WaitForLastOperation+0x20>
 80012ac:	1c60      	adds	r0, r4, #1
 80012ae:	b138      	cbz	r0, 80012c0 <FLASH_WaitForLastOperation+0x20>
 80012b0:	b124      	cbz	r4, 80012bc <FLASH_WaitForLastOperation+0x1c>
 80012b2:	f001 fee1 	bl	8003078 <HAL_GetTick>
 80012b6:	1b40      	subs	r0, r0, r5
 80012b8:	42a0      	cmp	r0, r4
 80012ba:	d901      	bls.n	80012c0 <FLASH_WaitForLastOperation+0x20>
 80012bc:	2003      	movs	r0, #3
 80012be:	bd70      	pop	{r4, r5, r6, pc}
 80012c0:	4812      	ldr	r0, [pc, #72]	@ (800130c <FLASH_WaitForLastOperation+0x6c>)
 80012c2:	68c0      	ldr	r0, [r0, #12]
 80012c4:	f000 0001 	and.w	r0, r0, #1
 80012c8:	2800      	cmp	r0, #0
 80012ca:	d1ef      	bne.n	80012ac <FLASH_WaitForLastOperation+0xc>
 80012cc:	480f      	ldr	r0, [pc, #60]	@ (800130c <FLASH_WaitForLastOperation+0x6c>)
 80012ce:	68c0      	ldr	r0, [r0, #12]
 80012d0:	f000 0020 	and.w	r0, r0, #32
 80012d4:	b120      	cbz	r0, 80012e0 <FLASH_WaitForLastOperation+0x40>
 80012d6:	bf00      	nop
 80012d8:	2020      	movs	r0, #32
 80012da:	490c      	ldr	r1, [pc, #48]	@ (800130c <FLASH_WaitForLastOperation+0x6c>)
 80012dc:	60c8      	str	r0, [r1, #12]
 80012de:	bf00      	nop
 80012e0:	480a      	ldr	r0, [pc, #40]	@ (800130c <FLASH_WaitForLastOperation+0x6c>)
 80012e2:	68c0      	ldr	r0, [r0, #12]
 80012e4:	f000 0010 	and.w	r0, r0, #16
 80012e8:	b948      	cbnz	r0, 80012fe <FLASH_WaitForLastOperation+0x5e>
 80012ea:	4808      	ldr	r0, [pc, #32]	@ (800130c <FLASH_WaitForLastOperation+0x6c>)
 80012ec:	69c0      	ldr	r0, [r0, #28]
 80012ee:	f000 0001 	and.w	r0, r0, #1
 80012f2:	b920      	cbnz	r0, 80012fe <FLASH_WaitForLastOperation+0x5e>
 80012f4:	4805      	ldr	r0, [pc, #20]	@ (800130c <FLASH_WaitForLastOperation+0x6c>)
 80012f6:	68c0      	ldr	r0, [r0, #12]
 80012f8:	f000 0004 	and.w	r0, r0, #4
 80012fc:	b118      	cbz	r0, 8001306 <FLASH_WaitForLastOperation+0x66>
 80012fe:	f7ff ff8d 	bl	800121c <FLASH_SetErrorCode>
 8001302:	2001      	movs	r0, #1
 8001304:	e7db      	b.n	80012be <FLASH_WaitForLastOperation+0x1e>
 8001306:	2000      	movs	r0, #0
 8001308:	e7d9      	b.n	80012be <FLASH_WaitForLastOperation+0x1e>
 800130a:	0000      	.short	0x0000
 800130c:	40022000 	.word	0x40022000

08001310 <HAL_DBGMCU_DisableDBGSleepMode>:
 8001310:	4803      	ldr	r0, [pc, #12]	@ (8001320 <HAL_DBGMCU_DisableDBGSleepMode+0x10>)
 8001312:	6840      	ldr	r0, [r0, #4]
 8001314:	f020 0001 	bic.w	r0, r0, #1
 8001318:	4901      	ldr	r1, [pc, #4]	@ (8001320 <HAL_DBGMCU_DisableDBGSleepMode+0x10>)
 800131a:	6048      	str	r0, [r1, #4]
 800131c:	4770      	bx	lr
 800131e:	0000      	.short	0x0000
 8001320:	e0042000 	.word	0xe0042000

08001324 <HAL_DBGMCU_DisableDBGStandbyMode>:
 8001324:	4803      	ldr	r0, [pc, #12]	@ (8001334 <HAL_DBGMCU_DisableDBGStandbyMode+0x10>)
 8001326:	6840      	ldr	r0, [r0, #4]
 8001328:	f020 0004 	bic.w	r0, r0, #4
 800132c:	4901      	ldr	r1, [pc, #4]	@ (8001334 <HAL_DBGMCU_DisableDBGStandbyMode+0x10>)
 800132e:	6048      	str	r0, [r1, #4]
 8001330:	4770      	bx	lr
 8001332:	0000      	.short	0x0000
 8001334:	e0042000 	.word	0xe0042000

08001338 <HAL_DBGMCU_DisableDBGStopMode>:
 8001338:	4803      	ldr	r0, [pc, #12]	@ (8001348 <HAL_DBGMCU_DisableDBGStopMode+0x10>)
 800133a:	6840      	ldr	r0, [r0, #4]
 800133c:	f020 0002 	bic.w	r0, r0, #2
 8001340:	4901      	ldr	r1, [pc, #4]	@ (8001348 <HAL_DBGMCU_DisableDBGStopMode+0x10>)
 8001342:	6048      	str	r0, [r1, #4]
 8001344:	4770      	bx	lr
 8001346:	0000      	.short	0x0000
 8001348:	e0042000 	.word	0xe0042000

0800134c <HAL_DBGMCU_EnableDBGSleepMode>:
 800134c:	4803      	ldr	r0, [pc, #12]	@ (800135c <HAL_DBGMCU_EnableDBGSleepMode+0x10>)
 800134e:	6840      	ldr	r0, [r0, #4]
 8001350:	f040 0001 	orr.w	r0, r0, #1
 8001354:	4901      	ldr	r1, [pc, #4]	@ (800135c <HAL_DBGMCU_EnableDBGSleepMode+0x10>)
 8001356:	6048      	str	r0, [r1, #4]
 8001358:	4770      	bx	lr
 800135a:	0000      	.short	0x0000
 800135c:	e0042000 	.word	0xe0042000

08001360 <HAL_DBGMCU_EnableDBGStandbyMode>:
 8001360:	4803      	ldr	r0, [pc, #12]	@ (8001370 <HAL_DBGMCU_EnableDBGStandbyMode+0x10>)
 8001362:	6840      	ldr	r0, [r0, #4]
 8001364:	f040 0004 	orr.w	r0, r0, #4
 8001368:	4901      	ldr	r1, [pc, #4]	@ (8001370 <HAL_DBGMCU_EnableDBGStandbyMode+0x10>)
 800136a:	6048      	str	r0, [r1, #4]
 800136c:	4770      	bx	lr
 800136e:	0000      	.short	0x0000
 8001370:	e0042000 	.word	0xe0042000

08001374 <HAL_DBGMCU_EnableDBGStopMode>:
 8001374:	4803      	ldr	r0, [pc, #12]	@ (8001384 <HAL_DBGMCU_EnableDBGStopMode+0x10>)
 8001376:	6840      	ldr	r0, [r0, #4]
 8001378:	f040 0002 	orr.w	r0, r0, #2
 800137c:	4901      	ldr	r1, [pc, #4]	@ (8001384 <HAL_DBGMCU_EnableDBGStopMode+0x10>)
 800137e:	6048      	str	r0, [r1, #4]
 8001380:	4770      	bx	lr
 8001382:	0000      	.short	0x0000
 8001384:	e0042000 	.word	0xe0042000

08001388 <HAL_DMA_Abort>:
 8001388:	4601      	mov	r1, r0
 800138a:	2200      	movs	r2, #0
 800138c:	f891 0021 	ldrb.w	r0, [r1, #33]	@ 0x21
 8001390:	2802      	cmp	r0, #2
 8001392:	d008      	beq.n	80013a6 <HAL_DMA_Abort+0x1e>
 8001394:	2004      	movs	r0, #4
 8001396:	6388      	str	r0, [r1, #56]	@ 0x38
 8001398:	bf00      	nop
 800139a:	2000      	movs	r0, #0
 800139c:	f881 0020 	strb.w	r0, [r1, #32]
 80013a0:	bf00      	nop
 80013a2:	2001      	movs	r0, #1
 80013a4:	4770      	bx	lr
 80013a6:	6808      	ldr	r0, [r1, #0]
 80013a8:	6800      	ldr	r0, [r0, #0]
 80013aa:	f020 000e 	bic.w	r0, r0, #14
 80013ae:	680b      	ldr	r3, [r1, #0]
 80013b0:	6018      	str	r0, [r3, #0]
 80013b2:	6808      	ldr	r0, [r1, #0]
 80013b4:	6800      	ldr	r0, [r0, #0]
 80013b6:	f020 0001 	bic.w	r0, r0, #1
 80013ba:	680b      	ldr	r3, [r1, #0]
 80013bc:	6018      	str	r0, [r3, #0]
 80013be:	f891 3040 	ldrb.w	r3, [r1, #64]	@ 0x40
 80013c2:	2001      	movs	r0, #1
 80013c4:	4098      	lsls	r0, r3
 80013c6:	6bcb      	ldr	r3, [r1, #60]	@ 0x3c
 80013c8:	6058      	str	r0, [r3, #4]
 80013ca:	2001      	movs	r0, #1
 80013cc:	f881 0021 	strb.w	r0, [r1, #33]	@ 0x21
 80013d0:	bf00      	nop
 80013d2:	2000      	movs	r0, #0
 80013d4:	f881 0020 	strb.w	r0, [r1, #32]
 80013d8:	bf00      	nop
 80013da:	4610      	mov	r0, r2
 80013dc:	e7e2      	b.n	80013a4 <HAL_DMA_Abort+0x1c>
	...

080013e0 <HAL_DMA_Abort_IT>:
 80013e0:	b570      	push	{r4, r5, r6, lr}
 80013e2:	4604      	mov	r4, r0
 80013e4:	2500      	movs	r5, #0
 80013e6:	f894 0021 	ldrb.w	r0, [r4, #33]	@ 0x21
 80013ea:	2802      	cmp	r0, #2
 80013ec:	d003      	beq.n	80013f6 <HAL_DMA_Abort_IT+0x16>
 80013ee:	2004      	movs	r0, #4
 80013f0:	63a0      	str	r0, [r4, #56]	@ 0x38
 80013f2:	2501      	movs	r5, #1
 80013f4:	e0c1      	b.n	800157a <HAL_DMA_Abort_IT+0x19a>
 80013f6:	6820      	ldr	r0, [r4, #0]
 80013f8:	6800      	ldr	r0, [r0, #0]
 80013fa:	f020 000e 	bic.w	r0, r0, #14
 80013fe:	6821      	ldr	r1, [r4, #0]
 8001400:	6008      	str	r0, [r1, #0]
 8001402:	6820      	ldr	r0, [r4, #0]
 8001404:	6800      	ldr	r0, [r0, #0]
 8001406:	f020 0001 	bic.w	r0, r0, #1
 800140a:	6821      	ldr	r1, [r4, #0]
 800140c:	6008      	str	r0, [r1, #0]
 800140e:	495c      	ldr	r1, [pc, #368]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001410:	6820      	ldr	r0, [r4, #0]
 8001412:	4288      	cmp	r0, r1
 8001414:	d952      	bls.n	80014bc <HAL_DMA_Abort_IT+0xdc>
 8001416:	495a      	ldr	r1, [pc, #360]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001418:	3978      	subs	r1, #120	@ 0x78
 800141a:	6820      	ldr	r0, [r4, #0]
 800141c:	4288      	cmp	r0, r1
 800141e:	d101      	bne.n	8001424 <HAL_DMA_Abort_IT+0x44>
 8001420:	2001      	movs	r0, #1
 8001422:	e047      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 8001424:	4956      	ldr	r1, [pc, #344]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001426:	3964      	subs	r1, #100	@ 0x64
 8001428:	6820      	ldr	r0, [r4, #0]
 800142a:	4288      	cmp	r0, r1
 800142c:	d101      	bne.n	8001432 <HAL_DMA_Abort_IT+0x52>
 800142e:	2010      	movs	r0, #16
 8001430:	e040      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 8001432:	4953      	ldr	r1, [pc, #332]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001434:	3950      	subs	r1, #80	@ 0x50
 8001436:	6820      	ldr	r0, [r4, #0]
 8001438:	4288      	cmp	r0, r1
 800143a:	d101      	bne.n	8001440 <HAL_DMA_Abort_IT+0x60>
 800143c:	1580      	asrs	r0, r0, #22
 800143e:	e039      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 8001440:	494f      	ldr	r1, [pc, #316]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001442:	393c      	subs	r1, #60	@ 0x3c
 8001444:	6820      	ldr	r0, [r4, #0]
 8001446:	4288      	cmp	r0, r1
 8001448:	d101      	bne.n	800144e <HAL_DMA_Abort_IT+0x6e>
 800144a:	1480      	asrs	r0, r0, #18
 800144c:	e032      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 800144e:	494c      	ldr	r1, [pc, #304]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001450:	3928      	subs	r1, #40	@ 0x28
 8001452:	6820      	ldr	r0, [r4, #0]
 8001454:	4288      	cmp	r0, r1
 8001456:	d102      	bne.n	800145e <HAL_DMA_Abort_IT+0x7e>
 8001458:	f44f 3080 	mov.w	r0, #65536	@ 0x10000
 800145c:	e02a      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 800145e:	4948      	ldr	r1, [pc, #288]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001460:	3914      	subs	r1, #20
 8001462:	6820      	ldr	r0, [r4, #0]
 8001464:	4288      	cmp	r0, r1
 8001466:	d102      	bne.n	800146e <HAL_DMA_Abort_IT+0x8e>
 8001468:	f44f 1080 	mov.w	r0, #1048576	@ 0x100000
 800146c:	e022      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 800146e:	4944      	ldr	r1, [pc, #272]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001470:	6820      	ldr	r0, [r4, #0]
 8001472:	4288      	cmp	r0, r1
 8001474:	d101      	bne.n	800147a <HAL_DMA_Abort_IT+0x9a>
 8001476:	0440      	lsls	r0, r0, #17
 8001478:	e01c      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 800147a:	4942      	ldr	r1, [pc, #264]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 800147c:	6820      	ldr	r0, [r4, #0]
 800147e:	4288      	cmp	r0, r1
 8001480:	d101      	bne.n	8001486 <HAL_DMA_Abort_IT+0xa6>
 8001482:	2001      	movs	r0, #1
 8001484:	e016      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 8001486:	493f      	ldr	r1, [pc, #252]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 8001488:	3114      	adds	r1, #20
 800148a:	6820      	ldr	r0, [r4, #0]
 800148c:	4288      	cmp	r0, r1
 800148e:	d101      	bne.n	8001494 <HAL_DMA_Abort_IT+0xb4>
 8001490:	2010      	movs	r0, #16
 8001492:	e00f      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 8001494:	493b      	ldr	r1, [pc, #236]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 8001496:	3128      	adds	r1, #40	@ 0x28
 8001498:	6820      	ldr	r0, [r4, #0]
 800149a:	4288      	cmp	r0, r1
 800149c:	d101      	bne.n	80014a2 <HAL_DMA_Abort_IT+0xc2>
 800149e:	1580      	asrs	r0, r0, #22
 80014a0:	e008      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 80014a2:	4938      	ldr	r1, [pc, #224]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 80014a4:	313c      	adds	r1, #60	@ 0x3c
 80014a6:	6820      	ldr	r0, [r4, #0]
 80014a8:	4288      	cmp	r0, r1
 80014aa:	d101      	bne.n	80014b0 <HAL_DMA_Abort_IT+0xd0>
 80014ac:	1480      	asrs	r0, r0, #18
 80014ae:	e001      	b.n	80014b4 <HAL_DMA_Abort_IT+0xd4>
 80014b0:	f44f 3080 	mov.w	r0, #65536	@ 0x10000
 80014b4:	4933      	ldr	r1, [pc, #204]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 80014b6:	1f09      	subs	r1, r1, #4
 80014b8:	6008      	str	r0, [r1, #0]
 80014ba:	e051      	b.n	8001560 <HAL_DMA_Abort_IT+0x180>
 80014bc:	4930      	ldr	r1, [pc, #192]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 80014be:	3978      	subs	r1, #120	@ 0x78
 80014c0:	6820      	ldr	r0, [r4, #0]
 80014c2:	4288      	cmp	r0, r1
 80014c4:	d101      	bne.n	80014ca <HAL_DMA_Abort_IT+0xea>
 80014c6:	2001      	movs	r0, #1
 80014c8:	e047      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 80014ca:	492d      	ldr	r1, [pc, #180]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 80014cc:	3964      	subs	r1, #100	@ 0x64
 80014ce:	6820      	ldr	r0, [r4, #0]
 80014d0:	4288      	cmp	r0, r1
 80014d2:	d101      	bne.n	80014d8 <HAL_DMA_Abort_IT+0xf8>
 80014d4:	2010      	movs	r0, #16
 80014d6:	e040      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 80014d8:	4929      	ldr	r1, [pc, #164]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 80014da:	3950      	subs	r1, #80	@ 0x50
 80014dc:	6820      	ldr	r0, [r4, #0]
 80014de:	4288      	cmp	r0, r1
 80014e0:	d101      	bne.n	80014e6 <HAL_DMA_Abort_IT+0x106>
 80014e2:	1580      	asrs	r0, r0, #22
 80014e4:	e039      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 80014e6:	4926      	ldr	r1, [pc, #152]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 80014e8:	393c      	subs	r1, #60	@ 0x3c
 80014ea:	6820      	ldr	r0, [r4, #0]
 80014ec:	4288      	cmp	r0, r1
 80014ee:	d101      	bne.n	80014f4 <HAL_DMA_Abort_IT+0x114>
 80014f0:	1480      	asrs	r0, r0, #18
 80014f2:	e032      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 80014f4:	4922      	ldr	r1, [pc, #136]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 80014f6:	3928      	subs	r1, #40	@ 0x28
 80014f8:	6820      	ldr	r0, [r4, #0]
 80014fa:	4288      	cmp	r0, r1
 80014fc:	d102      	bne.n	8001504 <HAL_DMA_Abort_IT+0x124>
 80014fe:	f44f 3080 	mov.w	r0, #65536	@ 0x10000
 8001502:	e02a      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 8001504:	491e      	ldr	r1, [pc, #120]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001506:	3914      	subs	r1, #20
 8001508:	6820      	ldr	r0, [r4, #0]
 800150a:	4288      	cmp	r0, r1
 800150c:	d102      	bne.n	8001514 <HAL_DMA_Abort_IT+0x134>
 800150e:	f44f 1080 	mov.w	r0, #1048576	@ 0x100000
 8001512:	e022      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 8001514:	491a      	ldr	r1, [pc, #104]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 8001516:	6820      	ldr	r0, [r4, #0]
 8001518:	4288      	cmp	r0, r1
 800151a:	d101      	bne.n	8001520 <HAL_DMA_Abort_IT+0x140>
 800151c:	0440      	lsls	r0, r0, #17
 800151e:	e01c      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 8001520:	4918      	ldr	r1, [pc, #96]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 8001522:	6820      	ldr	r0, [r4, #0]
 8001524:	4288      	cmp	r0, r1
 8001526:	d101      	bne.n	800152c <HAL_DMA_Abort_IT+0x14c>
 8001528:	2001      	movs	r0, #1
 800152a:	e016      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 800152c:	4915      	ldr	r1, [pc, #84]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 800152e:	3114      	adds	r1, #20
 8001530:	6820      	ldr	r0, [r4, #0]
 8001532:	4288      	cmp	r0, r1
 8001534:	d101      	bne.n	800153a <HAL_DMA_Abort_IT+0x15a>
 8001536:	2010      	movs	r0, #16
 8001538:	e00f      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 800153a:	4912      	ldr	r1, [pc, #72]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 800153c:	3128      	adds	r1, #40	@ 0x28
 800153e:	6820      	ldr	r0, [r4, #0]
 8001540:	4288      	cmp	r0, r1
 8001542:	d101      	bne.n	8001548 <HAL_DMA_Abort_IT+0x168>
 8001544:	1580      	asrs	r0, r0, #22
 8001546:	e008      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 8001548:	490e      	ldr	r1, [pc, #56]	@ (8001584 <HAL_DMA_Abort_IT+0x1a4>)
 800154a:	313c      	adds	r1, #60	@ 0x3c
 800154c:	6820      	ldr	r0, [r4, #0]
 800154e:	4288      	cmp	r0, r1
 8001550:	d101      	bne.n	8001556 <HAL_DMA_Abort_IT+0x176>
 8001552:	1480      	asrs	r0, r0, #18
 8001554:	e001      	b.n	800155a <HAL_DMA_Abort_IT+0x17a>
 8001556:	f44f 3080 	mov.w	r0, #65536	@ 0x10000
 800155a:	4909      	ldr	r1, [pc, #36]	@ (8001580 <HAL_DMA_Abort_IT+0x1a0>)
 800155c:	3980      	subs	r1, #128	@ 0x80
 800155e:	6048      	str	r0, [r1, #4]
 8001560:	2001      	movs	r0, #1
 8001562:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 8001566:	bf00      	nop
 8001568:	2000      	movs	r0, #0
 800156a:	f884 0020 	strb.w	r0, [r4, #32]
 800156e:	bf00      	nop
 8001570:	6b60      	ldr	r0, [r4, #52]	@ 0x34
 8001572:	b110      	cbz	r0, 800157a <HAL_DMA_Abort_IT+0x19a>
 8001574:	4620      	mov	r0, r4
 8001576:	6b61      	ldr	r1, [r4, #52]	@ 0x34
 8001578:	4788      	blx	r1
 800157a:	4628      	mov	r0, r5
 800157c:	bd70      	pop	{r4, r5, r6, pc}
 800157e:	0000      	.short	0x0000
 8001580:	40020080 	.word	0x40020080
 8001584:	40020408 	.word	0x40020408

08001588 <HAL_DMA_DeInit>:
 8001588:	4601      	mov	r1, r0
 800158a:	b909      	cbnz	r1, 8001590 <HAL_DMA_DeInit+0x8>
 800158c:	2001      	movs	r0, #1
 800158e:	4770      	bx	lr
 8001590:	6808      	ldr	r0, [r1, #0]
 8001592:	6800      	ldr	r0, [r0, #0]
 8001594:	f020 0001 	bic.w	r0, r0, #1
 8001598:	680a      	ldr	r2, [r1, #0]
 800159a:	6010      	str	r0, [r2, #0]
 800159c:	2000      	movs	r0, #0
 800159e:	680a      	ldr	r2, [r1, #0]
 80015a0:	6010      	str	r0, [r2, #0]
 80015a2:	680a      	ldr	r2, [r1, #0]
 80015a4:	6050      	str	r0, [r2, #4]
 80015a6:	680a      	ldr	r2, [r1, #0]
 80015a8:	6090      	str	r0, [r2, #8]
 80015aa:	680a      	ldr	r2, [r1, #0]
 80015ac:	60d0      	str	r0, [r2, #12]
 80015ae:	4a17      	ldr	r2, [pc, #92]	@ (800160c <HAL_DMA_DeInit+0x84>)
 80015b0:	6808      	ldr	r0, [r1, #0]
 80015b2:	4290      	cmp	r0, r2
 80015b4:	d20b      	bcs.n	80015ce <HAL_DMA_DeInit+0x46>
 80015b6:	4a16      	ldr	r2, [pc, #88]	@ (8001610 <HAL_DMA_DeInit+0x88>)
 80015b8:	6808      	ldr	r0, [r1, #0]
 80015ba:	1a80      	subs	r0, r0, r2
 80015bc:	2214      	movs	r2, #20
 80015be:	fbb0 f0f2 	udiv	r0, r0, r2
 80015c2:	0080      	lsls	r0, r0, #2
 80015c4:	6408      	str	r0, [r1, #64]	@ 0x40
 80015c6:	4812      	ldr	r0, [pc, #72]	@ (8001610 <HAL_DMA_DeInit+0x88>)
 80015c8:	3808      	subs	r0, #8
 80015ca:	63c8      	str	r0, [r1, #60]	@ 0x3c
 80015cc:	e00a      	b.n	80015e4 <HAL_DMA_DeInit+0x5c>
 80015ce:	4a0f      	ldr	r2, [pc, #60]	@ (800160c <HAL_DMA_DeInit+0x84>)
 80015d0:	6808      	ldr	r0, [r1, #0]
 80015d2:	1a80      	subs	r0, r0, r2
 80015d4:	2214      	movs	r2, #20
 80015d6:	fbb0 f0f2 	udiv	r0, r0, r2
 80015da:	0080      	lsls	r0, r0, #2
 80015dc:	6408      	str	r0, [r1, #64]	@ 0x40
 80015de:	480b      	ldr	r0, [pc, #44]	@ (800160c <HAL_DMA_DeInit+0x84>)
 80015e0:	3808      	subs	r0, #8
 80015e2:	63c8      	str	r0, [r1, #60]	@ 0x3c
 80015e4:	f891 2040 	ldrb.w	r2, [r1, #64]	@ 0x40
 80015e8:	2001      	movs	r0, #1
 80015ea:	4090      	lsls	r0, r2
 80015ec:	6bca      	ldr	r2, [r1, #60]	@ 0x3c
 80015ee:	6050      	str	r0, [r2, #4]
 80015f0:	2000      	movs	r0, #0
 80015f2:	6288      	str	r0, [r1, #40]	@ 0x28
 80015f4:	62c8      	str	r0, [r1, #44]	@ 0x2c
 80015f6:	6308      	str	r0, [r1, #48]	@ 0x30
 80015f8:	6348      	str	r0, [r1, #52]	@ 0x34
 80015fa:	6388      	str	r0, [r1, #56]	@ 0x38
 80015fc:	f881 0021 	strb.w	r0, [r1, #33]	@ 0x21
 8001600:	bf00      	nop
 8001602:	f881 0020 	strb.w	r0, [r1, #32]
 8001606:	bf00      	nop
 8001608:	bf00      	nop
 800160a:	e7c0      	b.n	800158e <HAL_DMA_DeInit+0x6>
 800160c:	40020408 	.word	0x40020408
 8001610:	40020008 	.word	0x40020008

08001614 <HAL_DMA_GetError>:
 8001614:	4601      	mov	r1, r0
 8001616:	6b88      	ldr	r0, [r1, #56]	@ 0x38
 8001618:	4770      	bx	lr

0800161a <HAL_DMA_GetState>:
 800161a:	4601      	mov	r1, r0
 800161c:	f891 0021 	ldrb.w	r0, [r1, #33]	@ 0x21
 8001620:	4770      	bx	lr
	...

08001624 <HAL_DMA_IRQHandler>:
 8001624:	b570      	push	{r4, r5, r6, lr}
 8001626:	4604      	mov	r4, r0
 8001628:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 800162a:	6805      	ldr	r5, [r0, #0]
 800162c:	6820      	ldr	r0, [r4, #0]
 800162e:	6806      	ldr	r6, [r0, #0]
 8001630:	f894 1040 	ldrb.w	r1, [r4, #64]	@ 0x40
 8001634:	2004      	movs	r0, #4
 8001636:	4088      	lsls	r0, r1
 8001638:	4028      	ands	r0, r5
 800163a:	2800      	cmp	r0, #0
 800163c:	d075      	beq.n	800172a <HAL_DMA_IRQHandler+0x106>
 800163e:	f006 0004 	and.w	r0, r6, #4
 8001642:	2800      	cmp	r0, #0
 8001644:	d0fa      	beq.n	800163c <HAL_DMA_IRQHandler+0x18>
 8001646:	6820      	ldr	r0, [r4, #0]
 8001648:	6800      	ldr	r0, [r0, #0]
 800164a:	f000 0020 	and.w	r0, r0, #32
 800164e:	b928      	cbnz	r0, 800165c <HAL_DMA_IRQHandler+0x38>
 8001650:	6820      	ldr	r0, [r4, #0]
 8001652:	6800      	ldr	r0, [r0, #0]
 8001654:	f020 0004 	bic.w	r0, r0, #4
 8001658:	6821      	ldr	r1, [r4, #0]
 800165a:	6008      	str	r0, [r1, #0]
 800165c:	49d5      	ldr	r1, [pc, #852]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800165e:	6820      	ldr	r0, [r4, #0]
 8001660:	4288      	cmp	r0, r1
 8001662:	d954      	bls.n	800170e <HAL_DMA_IRQHandler+0xea>
 8001664:	49d3      	ldr	r1, [pc, #844]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001666:	3978      	subs	r1, #120	@ 0x78
 8001668:	6820      	ldr	r0, [r4, #0]
 800166a:	4288      	cmp	r0, r1
 800166c:	d101      	bne.n	8001672 <HAL_DMA_IRQHandler+0x4e>
 800166e:	2004      	movs	r0, #4
 8001670:	e049      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 8001672:	49d0      	ldr	r1, [pc, #832]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001674:	3964      	subs	r1, #100	@ 0x64
 8001676:	6820      	ldr	r0, [r4, #0]
 8001678:	4288      	cmp	r0, r1
 800167a:	d101      	bne.n	8001680 <HAL_DMA_IRQHandler+0x5c>
 800167c:	2040      	movs	r0, #64	@ 0x40
 800167e:	e042      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 8001680:	49cc      	ldr	r1, [pc, #816]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001682:	3950      	subs	r1, #80	@ 0x50
 8001684:	6820      	ldr	r0, [r4, #0]
 8001686:	4288      	cmp	r0, r1
 8001688:	d101      	bne.n	800168e <HAL_DMA_IRQHandler+0x6a>
 800168a:	1500      	asrs	r0, r0, #20
 800168c:	e03b      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 800168e:	49c9      	ldr	r1, [pc, #804]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001690:	393c      	subs	r1, #60	@ 0x3c
 8001692:	6820      	ldr	r0, [r4, #0]
 8001694:	4288      	cmp	r0, r1
 8001696:	d102      	bne.n	800169e <HAL_DMA_IRQHandler+0x7a>
 8001698:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 800169c:	e033      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 800169e:	49c5      	ldr	r1, [pc, #788]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80016a0:	3928      	subs	r1, #40	@ 0x28
 80016a2:	6820      	ldr	r0, [r4, #0]
 80016a4:	4288      	cmp	r0, r1
 80016a6:	d102      	bne.n	80016ae <HAL_DMA_IRQHandler+0x8a>
 80016a8:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 80016ac:	e02b      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 80016ae:	49c1      	ldr	r1, [pc, #772]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80016b0:	3914      	subs	r1, #20
 80016b2:	6820      	ldr	r0, [r4, #0]
 80016b4:	4288      	cmp	r0, r1
 80016b6:	d102      	bne.n	80016be <HAL_DMA_IRQHandler+0x9a>
 80016b8:	f44f 0080 	mov.w	r0, #4194304	@ 0x400000
 80016bc:	e023      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 80016be:	49bd      	ldr	r1, [pc, #756]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80016c0:	6820      	ldr	r0, [r4, #0]
 80016c2:	4288      	cmp	r0, r1
 80016c4:	d101      	bne.n	80016ca <HAL_DMA_IRQHandler+0xa6>
 80016c6:	04c0      	lsls	r0, r0, #19
 80016c8:	e01d      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 80016ca:	49bb      	ldr	r1, [pc, #748]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 80016cc:	6820      	ldr	r0, [r4, #0]
 80016ce:	4288      	cmp	r0, r1
 80016d0:	d101      	bne.n	80016d6 <HAL_DMA_IRQHandler+0xb2>
 80016d2:	2004      	movs	r0, #4
 80016d4:	e017      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 80016d6:	49b8      	ldr	r1, [pc, #736]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 80016d8:	3114      	adds	r1, #20
 80016da:	6820      	ldr	r0, [r4, #0]
 80016dc:	4288      	cmp	r0, r1
 80016de:	d101      	bne.n	80016e4 <HAL_DMA_IRQHandler+0xc0>
 80016e0:	2040      	movs	r0, #64	@ 0x40
 80016e2:	e010      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 80016e4:	49b4      	ldr	r1, [pc, #720]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 80016e6:	3128      	adds	r1, #40	@ 0x28
 80016e8:	6820      	ldr	r0, [r4, #0]
 80016ea:	4288      	cmp	r0, r1
 80016ec:	d101      	bne.n	80016f2 <HAL_DMA_IRQHandler+0xce>
 80016ee:	1500      	asrs	r0, r0, #20
 80016f0:	e009      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 80016f2:	49b1      	ldr	r1, [pc, #708]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 80016f4:	313c      	adds	r1, #60	@ 0x3c
 80016f6:	6820      	ldr	r0, [r4, #0]
 80016f8:	4288      	cmp	r0, r1
 80016fa:	d102      	bne.n	8001702 <HAL_DMA_IRQHandler+0xde>
 80016fc:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 8001700:	e001      	b.n	8001706 <HAL_DMA_IRQHandler+0xe2>
 8001702:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8001706:	49ac      	ldr	r1, [pc, #688]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001708:	1f09      	subs	r1, r1, #4
 800170a:	6008      	str	r0, [r1, #0]
 800170c:	e054      	b.n	80017b8 <HAL_DMA_IRQHandler+0x194>
 800170e:	49a9      	ldr	r1, [pc, #676]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001710:	3978      	subs	r1, #120	@ 0x78
 8001712:	6820      	ldr	r0, [r4, #0]
 8001714:	4288      	cmp	r0, r1
 8001716:	d101      	bne.n	800171c <HAL_DMA_IRQHandler+0xf8>
 8001718:	2004      	movs	r0, #4
 800171a:	e04a      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 800171c:	49a5      	ldr	r1, [pc, #660]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800171e:	3964      	subs	r1, #100	@ 0x64
 8001720:	6820      	ldr	r0, [r4, #0]
 8001722:	4288      	cmp	r0, r1
 8001724:	d102      	bne.n	800172c <HAL_DMA_IRQHandler+0x108>
 8001726:	2040      	movs	r0, #64	@ 0x40
 8001728:	e043      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 800172a:	e04c      	b.n	80017c6 <HAL_DMA_IRQHandler+0x1a2>
 800172c:	49a1      	ldr	r1, [pc, #644]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800172e:	3950      	subs	r1, #80	@ 0x50
 8001730:	6820      	ldr	r0, [r4, #0]
 8001732:	4288      	cmp	r0, r1
 8001734:	d101      	bne.n	800173a <HAL_DMA_IRQHandler+0x116>
 8001736:	1500      	asrs	r0, r0, #20
 8001738:	e03b      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 800173a:	499e      	ldr	r1, [pc, #632]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800173c:	393c      	subs	r1, #60	@ 0x3c
 800173e:	6820      	ldr	r0, [r4, #0]
 8001740:	4288      	cmp	r0, r1
 8001742:	d102      	bne.n	800174a <HAL_DMA_IRQHandler+0x126>
 8001744:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 8001748:	e033      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 800174a:	499a      	ldr	r1, [pc, #616]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800174c:	3928      	subs	r1, #40	@ 0x28
 800174e:	6820      	ldr	r0, [r4, #0]
 8001750:	4288      	cmp	r0, r1
 8001752:	d102      	bne.n	800175a <HAL_DMA_IRQHandler+0x136>
 8001754:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8001758:	e02b      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 800175a:	4996      	ldr	r1, [pc, #600]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800175c:	3914      	subs	r1, #20
 800175e:	6820      	ldr	r0, [r4, #0]
 8001760:	4288      	cmp	r0, r1
 8001762:	d102      	bne.n	800176a <HAL_DMA_IRQHandler+0x146>
 8001764:	f44f 0080 	mov.w	r0, #4194304	@ 0x400000
 8001768:	e023      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 800176a:	4992      	ldr	r1, [pc, #584]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800176c:	6820      	ldr	r0, [r4, #0]
 800176e:	4288      	cmp	r0, r1
 8001770:	d101      	bne.n	8001776 <HAL_DMA_IRQHandler+0x152>
 8001772:	04c0      	lsls	r0, r0, #19
 8001774:	e01d      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 8001776:	4990      	ldr	r1, [pc, #576]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001778:	6820      	ldr	r0, [r4, #0]
 800177a:	4288      	cmp	r0, r1
 800177c:	d101      	bne.n	8001782 <HAL_DMA_IRQHandler+0x15e>
 800177e:	2004      	movs	r0, #4
 8001780:	e017      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 8001782:	498d      	ldr	r1, [pc, #564]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001784:	3114      	adds	r1, #20
 8001786:	6820      	ldr	r0, [r4, #0]
 8001788:	4288      	cmp	r0, r1
 800178a:	d101      	bne.n	8001790 <HAL_DMA_IRQHandler+0x16c>
 800178c:	2040      	movs	r0, #64	@ 0x40
 800178e:	e010      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 8001790:	4989      	ldr	r1, [pc, #548]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001792:	3128      	adds	r1, #40	@ 0x28
 8001794:	6820      	ldr	r0, [r4, #0]
 8001796:	4288      	cmp	r0, r1
 8001798:	d101      	bne.n	800179e <HAL_DMA_IRQHandler+0x17a>
 800179a:	1500      	asrs	r0, r0, #20
 800179c:	e009      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 800179e:	4986      	ldr	r1, [pc, #536]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 80017a0:	313c      	adds	r1, #60	@ 0x3c
 80017a2:	6820      	ldr	r0, [r4, #0]
 80017a4:	4288      	cmp	r0, r1
 80017a6:	d102      	bne.n	80017ae <HAL_DMA_IRQHandler+0x18a>
 80017a8:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 80017ac:	e001      	b.n	80017b2 <HAL_DMA_IRQHandler+0x18e>
 80017ae:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 80017b2:	4980      	ldr	r1, [pc, #512]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80017b4:	3980      	subs	r1, #128	@ 0x80
 80017b6:	6048      	str	r0, [r1, #4]
 80017b8:	6ae0      	ldr	r0, [r4, #44]	@ 0x2c
 80017ba:	2800      	cmp	r0, #0
 80017bc:	d002      	beq.n	80017c4 <HAL_DMA_IRQHandler+0x1a0>
 80017be:	4620      	mov	r0, r4
 80017c0:	6ae1      	ldr	r1, [r4, #44]	@ 0x2c
 80017c2:	4788      	blx	r1
 80017c4:	e0f4      	b.n	80019b0 <HAL_DMA_IRQHandler+0x38c>
 80017c6:	f894 1040 	ldrb.w	r1, [r4, #64]	@ 0x40
 80017ca:	2002      	movs	r0, #2
 80017cc:	4088      	lsls	r0, r1
 80017ce:	4028      	ands	r0, r5
 80017d0:	2800      	cmp	r0, #0
 80017d2:	d071      	beq.n	80018b8 <HAL_DMA_IRQHandler+0x294>
 80017d4:	f006 0002 	and.w	r0, r6, #2
 80017d8:	2800      	cmp	r0, #0
 80017da:	d0fa      	beq.n	80017d2 <HAL_DMA_IRQHandler+0x1ae>
 80017dc:	6820      	ldr	r0, [r4, #0]
 80017de:	6800      	ldr	r0, [r0, #0]
 80017e0:	f000 0020 	and.w	r0, r0, #32
 80017e4:	b940      	cbnz	r0, 80017f8 <HAL_DMA_IRQHandler+0x1d4>
 80017e6:	6820      	ldr	r0, [r4, #0]
 80017e8:	6800      	ldr	r0, [r0, #0]
 80017ea:	f020 000a 	bic.w	r0, r0, #10
 80017ee:	6821      	ldr	r1, [r4, #0]
 80017f0:	6008      	str	r0, [r1, #0]
 80017f2:	2001      	movs	r0, #1
 80017f4:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 80017f8:	496e      	ldr	r1, [pc, #440]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80017fa:	6820      	ldr	r0, [r4, #0]
 80017fc:	4288      	cmp	r0, r1
 80017fe:	d954      	bls.n	80018aa <HAL_DMA_IRQHandler+0x286>
 8001800:	496c      	ldr	r1, [pc, #432]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001802:	3978      	subs	r1, #120	@ 0x78
 8001804:	6820      	ldr	r0, [r4, #0]
 8001806:	4288      	cmp	r0, r1
 8001808:	d101      	bne.n	800180e <HAL_DMA_IRQHandler+0x1ea>
 800180a:	2002      	movs	r0, #2
 800180c:	e049      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800180e:	4969      	ldr	r1, [pc, #420]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001810:	3964      	subs	r1, #100	@ 0x64
 8001812:	6820      	ldr	r0, [r4, #0]
 8001814:	4288      	cmp	r0, r1
 8001816:	d101      	bne.n	800181c <HAL_DMA_IRQHandler+0x1f8>
 8001818:	2020      	movs	r0, #32
 800181a:	e042      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800181c:	4965      	ldr	r1, [pc, #404]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800181e:	3950      	subs	r1, #80	@ 0x50
 8001820:	6820      	ldr	r0, [r4, #0]
 8001822:	4288      	cmp	r0, r1
 8001824:	d101      	bne.n	800182a <HAL_DMA_IRQHandler+0x206>
 8001826:	1540      	asrs	r0, r0, #21
 8001828:	e03b      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800182a:	4962      	ldr	r1, [pc, #392]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800182c:	393c      	subs	r1, #60	@ 0x3c
 800182e:	6820      	ldr	r0, [r4, #0]
 8001830:	4288      	cmp	r0, r1
 8001832:	d102      	bne.n	800183a <HAL_DMA_IRQHandler+0x216>
 8001834:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001838:	e033      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800183a:	495e      	ldr	r1, [pc, #376]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800183c:	3928      	subs	r1, #40	@ 0x28
 800183e:	6820      	ldr	r0, [r4, #0]
 8001840:	4288      	cmp	r0, r1
 8001842:	d102      	bne.n	800184a <HAL_DMA_IRQHandler+0x226>
 8001844:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 8001848:	e02b      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800184a:	495a      	ldr	r1, [pc, #360]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800184c:	3914      	subs	r1, #20
 800184e:	6820      	ldr	r0, [r4, #0]
 8001850:	4288      	cmp	r0, r1
 8001852:	d102      	bne.n	800185a <HAL_DMA_IRQHandler+0x236>
 8001854:	f44f 1000 	mov.w	r0, #2097152	@ 0x200000
 8001858:	e023      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800185a:	4956      	ldr	r1, [pc, #344]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 800185c:	6820      	ldr	r0, [r4, #0]
 800185e:	4288      	cmp	r0, r1
 8001860:	d101      	bne.n	8001866 <HAL_DMA_IRQHandler+0x242>
 8001862:	0480      	lsls	r0, r0, #18
 8001864:	e01d      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 8001866:	4954      	ldr	r1, [pc, #336]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001868:	6820      	ldr	r0, [r4, #0]
 800186a:	4288      	cmp	r0, r1
 800186c:	d101      	bne.n	8001872 <HAL_DMA_IRQHandler+0x24e>
 800186e:	2002      	movs	r0, #2
 8001870:	e017      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 8001872:	4951      	ldr	r1, [pc, #324]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001874:	3114      	adds	r1, #20
 8001876:	6820      	ldr	r0, [r4, #0]
 8001878:	4288      	cmp	r0, r1
 800187a:	d101      	bne.n	8001880 <HAL_DMA_IRQHandler+0x25c>
 800187c:	2020      	movs	r0, #32
 800187e:	e010      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 8001880:	494d      	ldr	r1, [pc, #308]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001882:	3128      	adds	r1, #40	@ 0x28
 8001884:	6820      	ldr	r0, [r4, #0]
 8001886:	4288      	cmp	r0, r1
 8001888:	d101      	bne.n	800188e <HAL_DMA_IRQHandler+0x26a>
 800188a:	1540      	asrs	r0, r0, #21
 800188c:	e009      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800188e:	494a      	ldr	r1, [pc, #296]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001890:	313c      	adds	r1, #60	@ 0x3c
 8001892:	6820      	ldr	r0, [r4, #0]
 8001894:	4288      	cmp	r0, r1
 8001896:	d102      	bne.n	800189e <HAL_DMA_IRQHandler+0x27a>
 8001898:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 800189c:	e001      	b.n	80018a2 <HAL_DMA_IRQHandler+0x27e>
 800189e:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 80018a2:	4945      	ldr	r1, [pc, #276]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 80018a4:	1f09      	subs	r1, r1, #4
 80018a6:	6008      	str	r0, [r1, #0]
 80018a8:	e054      	b.n	8001954 <HAL_DMA_IRQHandler+0x330>
 80018aa:	4942      	ldr	r1, [pc, #264]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80018ac:	3978      	subs	r1, #120	@ 0x78
 80018ae:	6820      	ldr	r0, [r4, #0]
 80018b0:	4288      	cmp	r0, r1
 80018b2:	d102      	bne.n	80018ba <HAL_DMA_IRQHandler+0x296>
 80018b4:	2002      	movs	r0, #2
 80018b6:	e04a      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 80018b8:	e057      	b.n	800196a <HAL_DMA_IRQHandler+0x346>
 80018ba:	493e      	ldr	r1, [pc, #248]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80018bc:	3964      	subs	r1, #100	@ 0x64
 80018be:	6820      	ldr	r0, [r4, #0]
 80018c0:	4288      	cmp	r0, r1
 80018c2:	d101      	bne.n	80018c8 <HAL_DMA_IRQHandler+0x2a4>
 80018c4:	2020      	movs	r0, #32
 80018c6:	e042      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 80018c8:	493a      	ldr	r1, [pc, #232]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80018ca:	3950      	subs	r1, #80	@ 0x50
 80018cc:	6820      	ldr	r0, [r4, #0]
 80018ce:	4288      	cmp	r0, r1
 80018d0:	d101      	bne.n	80018d6 <HAL_DMA_IRQHandler+0x2b2>
 80018d2:	1540      	asrs	r0, r0, #21
 80018d4:	e03b      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 80018d6:	4937      	ldr	r1, [pc, #220]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80018d8:	393c      	subs	r1, #60	@ 0x3c
 80018da:	6820      	ldr	r0, [r4, #0]
 80018dc:	4288      	cmp	r0, r1
 80018de:	d102      	bne.n	80018e6 <HAL_DMA_IRQHandler+0x2c2>
 80018e0:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 80018e4:	e033      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 80018e6:	4933      	ldr	r1, [pc, #204]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80018e8:	3928      	subs	r1, #40	@ 0x28
 80018ea:	6820      	ldr	r0, [r4, #0]
 80018ec:	4288      	cmp	r0, r1
 80018ee:	d102      	bne.n	80018f6 <HAL_DMA_IRQHandler+0x2d2>
 80018f0:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 80018f4:	e02b      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 80018f6:	492f      	ldr	r1, [pc, #188]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 80018f8:	3914      	subs	r1, #20
 80018fa:	6820      	ldr	r0, [r4, #0]
 80018fc:	4288      	cmp	r0, r1
 80018fe:	d102      	bne.n	8001906 <HAL_DMA_IRQHandler+0x2e2>
 8001900:	f44f 1000 	mov.w	r0, #2097152	@ 0x200000
 8001904:	e023      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 8001906:	492b      	ldr	r1, [pc, #172]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001908:	6820      	ldr	r0, [r4, #0]
 800190a:	4288      	cmp	r0, r1
 800190c:	d101      	bne.n	8001912 <HAL_DMA_IRQHandler+0x2ee>
 800190e:	0480      	lsls	r0, r0, #18
 8001910:	e01d      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 8001912:	4929      	ldr	r1, [pc, #164]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001914:	6820      	ldr	r0, [r4, #0]
 8001916:	4288      	cmp	r0, r1
 8001918:	d101      	bne.n	800191e <HAL_DMA_IRQHandler+0x2fa>
 800191a:	2002      	movs	r0, #2
 800191c:	e017      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 800191e:	4926      	ldr	r1, [pc, #152]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 8001920:	3114      	adds	r1, #20
 8001922:	6820      	ldr	r0, [r4, #0]
 8001924:	4288      	cmp	r0, r1
 8001926:	d101      	bne.n	800192c <HAL_DMA_IRQHandler+0x308>
 8001928:	2020      	movs	r0, #32
 800192a:	e010      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 800192c:	4922      	ldr	r1, [pc, #136]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 800192e:	3128      	adds	r1, #40	@ 0x28
 8001930:	6820      	ldr	r0, [r4, #0]
 8001932:	4288      	cmp	r0, r1
 8001934:	d101      	bne.n	800193a <HAL_DMA_IRQHandler+0x316>
 8001936:	1540      	asrs	r0, r0, #21
 8001938:	e009      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 800193a:	491f      	ldr	r1, [pc, #124]	@ (80019b8 <HAL_DMA_IRQHandler+0x394>)
 800193c:	313c      	adds	r1, #60	@ 0x3c
 800193e:	6820      	ldr	r0, [r4, #0]
 8001940:	4288      	cmp	r0, r1
 8001942:	d102      	bne.n	800194a <HAL_DMA_IRQHandler+0x326>
 8001944:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001948:	e001      	b.n	800194e <HAL_DMA_IRQHandler+0x32a>
 800194a:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 800194e:	4919      	ldr	r1, [pc, #100]	@ (80019b4 <HAL_DMA_IRQHandler+0x390>)
 8001950:	3980      	subs	r1, #128	@ 0x80
 8001952:	6048      	str	r0, [r1, #4]
 8001954:	bf00      	nop
 8001956:	2000      	movs	r0, #0
 8001958:	f884 0020 	strb.w	r0, [r4, #32]
 800195c:	bf00      	nop
 800195e:	6aa0      	ldr	r0, [r4, #40]	@ 0x28
 8001960:	b330      	cbz	r0, 80019b0 <HAL_DMA_IRQHandler+0x38c>
 8001962:	4620      	mov	r0, r4
 8001964:	6aa1      	ldr	r1, [r4, #40]	@ 0x28
 8001966:	4788      	blx	r1
 8001968:	e022      	b.n	80019b0 <HAL_DMA_IRQHandler+0x38c>
 800196a:	f894 1040 	ldrb.w	r1, [r4, #64]	@ 0x40
 800196e:	2008      	movs	r0, #8
 8001970:	4088      	lsls	r0, r1
 8001972:	4028      	ands	r0, r5
 8001974:	b1e0      	cbz	r0, 80019b0 <HAL_DMA_IRQHandler+0x38c>
 8001976:	f006 0008 	and.w	r0, r6, #8
 800197a:	b1c8      	cbz	r0, 80019b0 <HAL_DMA_IRQHandler+0x38c>
 800197c:	6820      	ldr	r0, [r4, #0]
 800197e:	6800      	ldr	r0, [r0, #0]
 8001980:	f020 000e 	bic.w	r0, r0, #14
 8001984:	6821      	ldr	r1, [r4, #0]
 8001986:	6008      	str	r0, [r1, #0]
 8001988:	f894 1040 	ldrb.w	r1, [r4, #64]	@ 0x40
 800198c:	2001      	movs	r0, #1
 800198e:	4088      	lsls	r0, r1
 8001990:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8001992:	6048      	str	r0, [r1, #4]
 8001994:	2001      	movs	r0, #1
 8001996:	63a0      	str	r0, [r4, #56]	@ 0x38
 8001998:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 800199c:	bf00      	nop
 800199e:	2000      	movs	r0, #0
 80019a0:	f884 0020 	strb.w	r0, [r4, #32]
 80019a4:	bf00      	nop
 80019a6:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 80019a8:	b110      	cbz	r0, 80019b0 <HAL_DMA_IRQHandler+0x38c>
 80019aa:	4620      	mov	r0, r4
 80019ac:	6b21      	ldr	r1, [r4, #48]	@ 0x30
 80019ae:	4788      	blx	r1
 80019b0:	bd70      	pop	{r4, r5, r6, pc}
 80019b2:	0000      	.short	0x0000
 80019b4:	40020080 	.word	0x40020080
 80019b8:	40020408 	.word	0x40020408

080019bc <HAL_DMA_Init>:
 80019bc:	4601      	mov	r1, r0
 80019be:	2200      	movs	r2, #0
 80019c0:	b909      	cbnz	r1, 80019c6 <HAL_DMA_Init+0xa>
 80019c2:	2001      	movs	r0, #1
 80019c4:	4770      	bx	lr
 80019c6:	4b1e      	ldr	r3, [pc, #120]	@ (8001a40 <HAL_DMA_Init+0x84>)
 80019c8:	6808      	ldr	r0, [r1, #0]
 80019ca:	4298      	cmp	r0, r3
 80019cc:	d20b      	bcs.n	80019e6 <HAL_DMA_Init+0x2a>
 80019ce:	4b1d      	ldr	r3, [pc, #116]	@ (8001a44 <HAL_DMA_Init+0x88>)
 80019d0:	6808      	ldr	r0, [r1, #0]
 80019d2:	1ac0      	subs	r0, r0, r3
 80019d4:	2314      	movs	r3, #20
 80019d6:	fbb0 f0f3 	udiv	r0, r0, r3
 80019da:	0080      	lsls	r0, r0, #2
 80019dc:	6408      	str	r0, [r1, #64]	@ 0x40
 80019de:	4819      	ldr	r0, [pc, #100]	@ (8001a44 <HAL_DMA_Init+0x88>)
 80019e0:	3808      	subs	r0, #8
 80019e2:	63c8      	str	r0, [r1, #60]	@ 0x3c
 80019e4:	e00a      	b.n	80019fc <HAL_DMA_Init+0x40>
 80019e6:	4b16      	ldr	r3, [pc, #88]	@ (8001a40 <HAL_DMA_Init+0x84>)
 80019e8:	6808      	ldr	r0, [r1, #0]
 80019ea:	1ac0      	subs	r0, r0, r3
 80019ec:	2314      	movs	r3, #20
 80019ee:	fbb0 f0f3 	udiv	r0, r0, r3
 80019f2:	0080      	lsls	r0, r0, #2
 80019f4:	6408      	str	r0, [r1, #64]	@ 0x40
 80019f6:	4812      	ldr	r0, [pc, #72]	@ (8001a40 <HAL_DMA_Init+0x84>)
 80019f8:	3808      	subs	r0, #8
 80019fa:	63c8      	str	r0, [r1, #60]	@ 0x3c
 80019fc:	2002      	movs	r0, #2
 80019fe:	f881 0021 	strb.w	r0, [r1, #33]	@ 0x21
 8001a02:	6808      	ldr	r0, [r1, #0]
 8001a04:	6802      	ldr	r2, [r0, #0]
 8001a06:	f643 70f0 	movw	r0, #16368	@ 0x3ff0
 8001a0a:	4382      	bics	r2, r0
 8001a0c:	e9d1 0301 	ldrd	r0, r3, [r1, #4]
 8001a10:	4318      	orrs	r0, r3
 8001a12:	68cb      	ldr	r3, [r1, #12]
 8001a14:	4318      	orrs	r0, r3
 8001a16:	690b      	ldr	r3, [r1, #16]
 8001a18:	4318      	orrs	r0, r3
 8001a1a:	694b      	ldr	r3, [r1, #20]
 8001a1c:	4318      	orrs	r0, r3
 8001a1e:	698b      	ldr	r3, [r1, #24]
 8001a20:	4318      	orrs	r0, r3
 8001a22:	69cb      	ldr	r3, [r1, #28]
 8001a24:	4318      	orrs	r0, r3
 8001a26:	4302      	orrs	r2, r0
 8001a28:	6808      	ldr	r0, [r1, #0]
 8001a2a:	6002      	str	r2, [r0, #0]
 8001a2c:	2000      	movs	r0, #0
 8001a2e:	6388      	str	r0, [r1, #56]	@ 0x38
 8001a30:	2001      	movs	r0, #1
 8001a32:	f881 0021 	strb.w	r0, [r1, #33]	@ 0x21
 8001a36:	2000      	movs	r0, #0
 8001a38:	f881 0020 	strb.w	r0, [r1, #32]
 8001a3c:	bf00      	nop
 8001a3e:	e7c1      	b.n	80019c4 <HAL_DMA_Init+0x8>
 8001a40:	40020408 	.word	0x40020408
 8001a44:	40020008 	.word	0x40020008

08001a48 <HAL_DMA_PollForTransfer>:
 8001a48:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 8001a4c:	4604      	mov	r4, r0
 8001a4e:	460e      	mov	r6, r1
 8001a50:	4615      	mov	r5, r2
 8001a52:	f04f 0800 	mov.w	r8, #0
 8001a56:	f894 0021 	ldrb.w	r0, [r4, #33]	@ 0x21
 8001a5a:	2802      	cmp	r0, #2
 8001a5c:	d009      	beq.n	8001a72 <HAL_DMA_PollForTransfer+0x2a>
 8001a5e:	2004      	movs	r0, #4
 8001a60:	63a0      	str	r0, [r4, #56]	@ 0x38
 8001a62:	bf00      	nop
 8001a64:	2000      	movs	r0, #0
 8001a66:	f884 0020 	strb.w	r0, [r4, #32]
 8001a6a:	bf00      	nop
 8001a6c:	2001      	movs	r0, #1
 8001a6e:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
 8001a72:	6820      	ldr	r0, [r4, #0]
 8001a74:	6800      	ldr	r0, [r0, #0]
 8001a76:	f000 0020 	and.w	r0, r0, #32
 8001a7a:	b120      	cbz	r0, 8001a86 <HAL_DMA_PollForTransfer+0x3e>
 8001a7c:	f44f 7080 	mov.w	r0, #256	@ 0x100
 8001a80:	63a0      	str	r0, [r4, #56]	@ 0x38
 8001a82:	2001      	movs	r0, #1
 8001a84:	e7f3      	b.n	8001a6e <HAL_DMA_PollForTransfer+0x26>
 8001a86:	2e00      	cmp	r6, #0
 8001a88:	d152      	bne.n	8001b30 <HAL_DMA_PollForTransfer+0xe8>
 8001a8a:	49f9      	ldr	r1, [pc, #996]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001a8c:	6820      	ldr	r0, [r4, #0]
 8001a8e:	4288      	cmp	r0, r1
 8001a90:	d101      	bne.n	8001a96 <HAL_DMA_PollForTransfer+0x4e>
 8001a92:	2002      	movs	r0, #2
 8001a94:	e04a      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001a96:	49f6      	ldr	r1, [pc, #984]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001a98:	3114      	adds	r1, #20
 8001a9a:	6820      	ldr	r0, [r4, #0]
 8001a9c:	4288      	cmp	r0, r1
 8001a9e:	d101      	bne.n	8001aa4 <HAL_DMA_PollForTransfer+0x5c>
 8001aa0:	2020      	movs	r0, #32
 8001aa2:	e043      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001aa4:	49f2      	ldr	r1, [pc, #968]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001aa6:	3128      	adds	r1, #40	@ 0x28
 8001aa8:	6820      	ldr	r0, [r4, #0]
 8001aaa:	4288      	cmp	r0, r1
 8001aac:	d101      	bne.n	8001ab2 <HAL_DMA_PollForTransfer+0x6a>
 8001aae:	1540      	asrs	r0, r0, #21
 8001ab0:	e03c      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001ab2:	49ef      	ldr	r1, [pc, #956]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001ab4:	313c      	adds	r1, #60	@ 0x3c
 8001ab6:	6820      	ldr	r0, [r4, #0]
 8001ab8:	4288      	cmp	r0, r1
 8001aba:	d102      	bne.n	8001ac2 <HAL_DMA_PollForTransfer+0x7a>
 8001abc:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001ac0:	e034      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001ac2:	49eb      	ldr	r1, [pc, #940]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001ac4:	3150      	adds	r1, #80	@ 0x50
 8001ac6:	6820      	ldr	r0, [r4, #0]
 8001ac8:	4288      	cmp	r0, r1
 8001aca:	d102      	bne.n	8001ad2 <HAL_DMA_PollForTransfer+0x8a>
 8001acc:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 8001ad0:	e02c      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001ad2:	49e7      	ldr	r1, [pc, #924]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001ad4:	3164      	adds	r1, #100	@ 0x64
 8001ad6:	6820      	ldr	r0, [r4, #0]
 8001ad8:	4288      	cmp	r0, r1
 8001ada:	d102      	bne.n	8001ae2 <HAL_DMA_PollForTransfer+0x9a>
 8001adc:	f44f 1000 	mov.w	r0, #2097152	@ 0x200000
 8001ae0:	e024      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001ae2:	49e3      	ldr	r1, [pc, #908]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001ae4:	3178      	adds	r1, #120	@ 0x78
 8001ae6:	6820      	ldr	r0, [r4, #0]
 8001ae8:	4288      	cmp	r0, r1
 8001aea:	d101      	bne.n	8001af0 <HAL_DMA_PollForTransfer+0xa8>
 8001aec:	0480      	lsls	r0, r0, #18
 8001aee:	e01d      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001af0:	49e0      	ldr	r1, [pc, #896]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001af2:	6820      	ldr	r0, [r4, #0]
 8001af4:	4288      	cmp	r0, r1
 8001af6:	d101      	bne.n	8001afc <HAL_DMA_PollForTransfer+0xb4>
 8001af8:	2002      	movs	r0, #2
 8001afa:	e017      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001afc:	49dd      	ldr	r1, [pc, #884]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001afe:	3114      	adds	r1, #20
 8001b00:	6820      	ldr	r0, [r4, #0]
 8001b02:	4288      	cmp	r0, r1
 8001b04:	d101      	bne.n	8001b0a <HAL_DMA_PollForTransfer+0xc2>
 8001b06:	2020      	movs	r0, #32
 8001b08:	e010      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001b0a:	49da      	ldr	r1, [pc, #872]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001b0c:	3128      	adds	r1, #40	@ 0x28
 8001b0e:	6820      	ldr	r0, [r4, #0]
 8001b10:	4288      	cmp	r0, r1
 8001b12:	d101      	bne.n	8001b18 <HAL_DMA_PollForTransfer+0xd0>
 8001b14:	1540      	asrs	r0, r0, #21
 8001b16:	e009      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001b18:	49d6      	ldr	r1, [pc, #856]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001b1a:	313c      	adds	r1, #60	@ 0x3c
 8001b1c:	6820      	ldr	r0, [r4, #0]
 8001b1e:	4288      	cmp	r0, r1
 8001b20:	d102      	bne.n	8001b28 <HAL_DMA_PollForTransfer+0xe0>
 8001b22:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001b26:	e001      	b.n	8001b2c <HAL_DMA_PollForTransfer+0xe4>
 8001b28:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 8001b2c:	4607      	mov	r7, r0
 8001b2e:	e051      	b.n	8001bd4 <HAL_DMA_PollForTransfer+0x18c>
 8001b30:	49cf      	ldr	r1, [pc, #828]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001b32:	6820      	ldr	r0, [r4, #0]
 8001b34:	4288      	cmp	r0, r1
 8001b36:	d101      	bne.n	8001b3c <HAL_DMA_PollForTransfer+0xf4>
 8001b38:	2004      	movs	r0, #4
 8001b3a:	e04a      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001b3c:	49cc      	ldr	r1, [pc, #816]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001b3e:	3114      	adds	r1, #20
 8001b40:	6820      	ldr	r0, [r4, #0]
 8001b42:	4288      	cmp	r0, r1
 8001b44:	d101      	bne.n	8001b4a <HAL_DMA_PollForTransfer+0x102>
 8001b46:	2040      	movs	r0, #64	@ 0x40
 8001b48:	e043      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001b4a:	49c9      	ldr	r1, [pc, #804]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001b4c:	3128      	adds	r1, #40	@ 0x28
 8001b4e:	6820      	ldr	r0, [r4, #0]
 8001b50:	4288      	cmp	r0, r1
 8001b52:	d101      	bne.n	8001b58 <HAL_DMA_PollForTransfer+0x110>
 8001b54:	1500      	asrs	r0, r0, #20
 8001b56:	e03c      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001b58:	49c5      	ldr	r1, [pc, #788]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001b5a:	313c      	adds	r1, #60	@ 0x3c
 8001b5c:	6820      	ldr	r0, [r4, #0]
 8001b5e:	4288      	cmp	r0, r1
 8001b60:	d102      	bne.n	8001b68 <HAL_DMA_PollForTransfer+0x120>
 8001b62:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 8001b66:	e034      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001b68:	49c1      	ldr	r1, [pc, #772]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001b6a:	3150      	adds	r1, #80	@ 0x50
 8001b6c:	6820      	ldr	r0, [r4, #0]
 8001b6e:	4288      	cmp	r0, r1
 8001b70:	d102      	bne.n	8001b78 <HAL_DMA_PollForTransfer+0x130>
 8001b72:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8001b76:	e02c      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001b78:	49bd      	ldr	r1, [pc, #756]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001b7a:	3164      	adds	r1, #100	@ 0x64
 8001b7c:	6820      	ldr	r0, [r4, #0]
 8001b7e:	4288      	cmp	r0, r1
 8001b80:	d102      	bne.n	8001b88 <HAL_DMA_PollForTransfer+0x140>
 8001b82:	f44f 0080 	mov.w	r0, #4194304	@ 0x400000
 8001b86:	e024      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001b88:	49b9      	ldr	r1, [pc, #740]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001b8a:	3178      	adds	r1, #120	@ 0x78
 8001b8c:	6820      	ldr	r0, [r4, #0]
 8001b8e:	4288      	cmp	r0, r1
 8001b90:	d101      	bne.n	8001b96 <HAL_DMA_PollForTransfer+0x14e>
 8001b92:	04c0      	lsls	r0, r0, #19
 8001b94:	e01d      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001b96:	49b7      	ldr	r1, [pc, #732]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001b98:	6820      	ldr	r0, [r4, #0]
 8001b9a:	4288      	cmp	r0, r1
 8001b9c:	d101      	bne.n	8001ba2 <HAL_DMA_PollForTransfer+0x15a>
 8001b9e:	2004      	movs	r0, #4
 8001ba0:	e017      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001ba2:	49b4      	ldr	r1, [pc, #720]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001ba4:	3114      	adds	r1, #20
 8001ba6:	6820      	ldr	r0, [r4, #0]
 8001ba8:	4288      	cmp	r0, r1
 8001baa:	d101      	bne.n	8001bb0 <HAL_DMA_PollForTransfer+0x168>
 8001bac:	2040      	movs	r0, #64	@ 0x40
 8001bae:	e010      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001bb0:	49b0      	ldr	r1, [pc, #704]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001bb2:	3128      	adds	r1, #40	@ 0x28
 8001bb4:	6820      	ldr	r0, [r4, #0]
 8001bb6:	4288      	cmp	r0, r1
 8001bb8:	d101      	bne.n	8001bbe <HAL_DMA_PollForTransfer+0x176>
 8001bba:	1500      	asrs	r0, r0, #20
 8001bbc:	e009      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001bbe:	49ad      	ldr	r1, [pc, #692]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001bc0:	313c      	adds	r1, #60	@ 0x3c
 8001bc2:	6820      	ldr	r0, [r4, #0]
 8001bc4:	4288      	cmp	r0, r1
 8001bc6:	d102      	bne.n	8001bce <HAL_DMA_PollForTransfer+0x186>
 8001bc8:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 8001bcc:	e001      	b.n	8001bd2 <HAL_DMA_PollForTransfer+0x18a>
 8001bce:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8001bd2:	4607      	mov	r7, r0
 8001bd4:	f001 fa50 	bl	8003078 <HAL_GetTick>
 8001bd8:	4680      	mov	r8, r0
 8001bda:	e0db      	b.n	8001d94 <HAL_DMA_PollForTransfer+0x34c>
 8001bdc:	49a4      	ldr	r1, [pc, #656]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001bde:	3178      	adds	r1, #120	@ 0x78
 8001be0:	6820      	ldr	r0, [r4, #0]
 8001be2:	4288      	cmp	r0, r1
 8001be4:	d955      	bls.n	8001c92 <HAL_DMA_PollForTransfer+0x24a>
 8001be6:	48a3      	ldr	r0, [pc, #652]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001be8:	3808      	subs	r0, #8
 8001bea:	6800      	ldr	r0, [r0, #0]
 8001bec:	4aa0      	ldr	r2, [pc, #640]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001bee:	6821      	ldr	r1, [r4, #0]
 8001bf0:	4291      	cmp	r1, r2
 8001bf2:	d101      	bne.n	8001bf8 <HAL_DMA_PollForTransfer+0x1b0>
 8001bf4:	2108      	movs	r1, #8
 8001bf6:	e04a      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001bf8:	4a9d      	ldr	r2, [pc, #628]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001bfa:	3214      	adds	r2, #20
 8001bfc:	6821      	ldr	r1, [r4, #0]
 8001bfe:	4291      	cmp	r1, r2
 8001c00:	d101      	bne.n	8001c06 <HAL_DMA_PollForTransfer+0x1be>
 8001c02:	2180      	movs	r1, #128	@ 0x80
 8001c04:	e043      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c06:	4a9a      	ldr	r2, [pc, #616]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001c08:	3228      	adds	r2, #40	@ 0x28
 8001c0a:	6821      	ldr	r1, [r4, #0]
 8001c0c:	4291      	cmp	r1, r2
 8001c0e:	d101      	bne.n	8001c14 <HAL_DMA_PollForTransfer+0x1cc>
 8001c10:	14c9      	asrs	r1, r1, #19
 8001c12:	e03c      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c14:	4a96      	ldr	r2, [pc, #600]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001c16:	323c      	adds	r2, #60	@ 0x3c
 8001c18:	6821      	ldr	r1, [r4, #0]
 8001c1a:	4291      	cmp	r1, r2
 8001c1c:	d102      	bne.n	8001c24 <HAL_DMA_PollForTransfer+0x1dc>
 8001c1e:	f44f 4100 	mov.w	r1, #32768	@ 0x8000
 8001c22:	e034      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c24:	4a92      	ldr	r2, [pc, #584]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001c26:	3250      	adds	r2, #80	@ 0x50
 8001c28:	6821      	ldr	r1, [r4, #0]
 8001c2a:	4291      	cmp	r1, r2
 8001c2c:	d102      	bne.n	8001c34 <HAL_DMA_PollForTransfer+0x1ec>
 8001c2e:	f44f 2100 	mov.w	r1, #524288	@ 0x80000
 8001c32:	e02c      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c34:	4a8e      	ldr	r2, [pc, #568]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001c36:	3264      	adds	r2, #100	@ 0x64
 8001c38:	6821      	ldr	r1, [r4, #0]
 8001c3a:	4291      	cmp	r1, r2
 8001c3c:	d102      	bne.n	8001c44 <HAL_DMA_PollForTransfer+0x1fc>
 8001c3e:	f44f 0100 	mov.w	r1, #8388608	@ 0x800000
 8001c42:	e024      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c44:	4a8a      	ldr	r2, [pc, #552]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001c46:	3278      	adds	r2, #120	@ 0x78
 8001c48:	6821      	ldr	r1, [r4, #0]
 8001c4a:	4291      	cmp	r1, r2
 8001c4c:	d101      	bne.n	8001c52 <HAL_DMA_PollForTransfer+0x20a>
 8001c4e:	0509      	lsls	r1, r1, #20
 8001c50:	e01d      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c52:	4a88      	ldr	r2, [pc, #544]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001c54:	6821      	ldr	r1, [r4, #0]
 8001c56:	4291      	cmp	r1, r2
 8001c58:	d101      	bne.n	8001c5e <HAL_DMA_PollForTransfer+0x216>
 8001c5a:	2108      	movs	r1, #8
 8001c5c:	e017      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c5e:	4a85      	ldr	r2, [pc, #532]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001c60:	3214      	adds	r2, #20
 8001c62:	6821      	ldr	r1, [r4, #0]
 8001c64:	4291      	cmp	r1, r2
 8001c66:	d101      	bne.n	8001c6c <HAL_DMA_PollForTransfer+0x224>
 8001c68:	2180      	movs	r1, #128	@ 0x80
 8001c6a:	e010      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c6c:	4a81      	ldr	r2, [pc, #516]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001c6e:	3228      	adds	r2, #40	@ 0x28
 8001c70:	6821      	ldr	r1, [r4, #0]
 8001c72:	4291      	cmp	r1, r2
 8001c74:	d101      	bne.n	8001c7a <HAL_DMA_PollForTransfer+0x232>
 8001c76:	14c9      	asrs	r1, r1, #19
 8001c78:	e009      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c7a:	4a7e      	ldr	r2, [pc, #504]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001c7c:	323c      	adds	r2, #60	@ 0x3c
 8001c7e:	6821      	ldr	r1, [r4, #0]
 8001c80:	4291      	cmp	r1, r2
 8001c82:	d102      	bne.n	8001c8a <HAL_DMA_PollForTransfer+0x242>
 8001c84:	f44f 4100 	mov.w	r1, #32768	@ 0x8000
 8001c88:	e001      	b.n	8001c8e <HAL_DMA_PollForTransfer+0x246>
 8001c8a:	f44f 2100 	mov.w	r1, #524288	@ 0x80000
 8001c8e:	4008      	ands	r0, r1
 8001c90:	e054      	b.n	8001d3c <HAL_DMA_PollForTransfer+0x2f4>
 8001c92:	4877      	ldr	r0, [pc, #476]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001c94:	3808      	subs	r0, #8
 8001c96:	6800      	ldr	r0, [r0, #0]
 8001c98:	4a75      	ldr	r2, [pc, #468]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001c9a:	6821      	ldr	r1, [r4, #0]
 8001c9c:	4291      	cmp	r1, r2
 8001c9e:	d101      	bne.n	8001ca4 <HAL_DMA_PollForTransfer+0x25c>
 8001ca0:	2108      	movs	r1, #8
 8001ca2:	e04a      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001ca4:	4a72      	ldr	r2, [pc, #456]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001ca6:	3214      	adds	r2, #20
 8001ca8:	6821      	ldr	r1, [r4, #0]
 8001caa:	4291      	cmp	r1, r2
 8001cac:	d101      	bne.n	8001cb2 <HAL_DMA_PollForTransfer+0x26a>
 8001cae:	2180      	movs	r1, #128	@ 0x80
 8001cb0:	e043      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001cb2:	4a6f      	ldr	r2, [pc, #444]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001cb4:	3228      	adds	r2, #40	@ 0x28
 8001cb6:	6821      	ldr	r1, [r4, #0]
 8001cb8:	4291      	cmp	r1, r2
 8001cba:	d101      	bne.n	8001cc0 <HAL_DMA_PollForTransfer+0x278>
 8001cbc:	14c9      	asrs	r1, r1, #19
 8001cbe:	e03c      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001cc0:	4a6b      	ldr	r2, [pc, #428]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001cc2:	323c      	adds	r2, #60	@ 0x3c
 8001cc4:	6821      	ldr	r1, [r4, #0]
 8001cc6:	4291      	cmp	r1, r2
 8001cc8:	d102      	bne.n	8001cd0 <HAL_DMA_PollForTransfer+0x288>
 8001cca:	f44f 4100 	mov.w	r1, #32768	@ 0x8000
 8001cce:	e034      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001cd0:	4a67      	ldr	r2, [pc, #412]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001cd2:	3250      	adds	r2, #80	@ 0x50
 8001cd4:	6821      	ldr	r1, [r4, #0]
 8001cd6:	4291      	cmp	r1, r2
 8001cd8:	d102      	bne.n	8001ce0 <HAL_DMA_PollForTransfer+0x298>
 8001cda:	f44f 2100 	mov.w	r1, #524288	@ 0x80000
 8001cde:	e02c      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001ce0:	4a63      	ldr	r2, [pc, #396]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001ce2:	3264      	adds	r2, #100	@ 0x64
 8001ce4:	6821      	ldr	r1, [r4, #0]
 8001ce6:	4291      	cmp	r1, r2
 8001ce8:	d102      	bne.n	8001cf0 <HAL_DMA_PollForTransfer+0x2a8>
 8001cea:	f44f 0100 	mov.w	r1, #8388608	@ 0x800000
 8001cee:	e024      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001cf0:	4a5f      	ldr	r2, [pc, #380]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001cf2:	3278      	adds	r2, #120	@ 0x78
 8001cf4:	6821      	ldr	r1, [r4, #0]
 8001cf6:	4291      	cmp	r1, r2
 8001cf8:	d101      	bne.n	8001cfe <HAL_DMA_PollForTransfer+0x2b6>
 8001cfa:	0509      	lsls	r1, r1, #20
 8001cfc:	e01d      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001cfe:	4a5d      	ldr	r2, [pc, #372]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001d00:	6821      	ldr	r1, [r4, #0]
 8001d02:	4291      	cmp	r1, r2
 8001d04:	d101      	bne.n	8001d0a <HAL_DMA_PollForTransfer+0x2c2>
 8001d06:	2108      	movs	r1, #8
 8001d08:	e017      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001d0a:	4a5a      	ldr	r2, [pc, #360]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001d0c:	3214      	adds	r2, #20
 8001d0e:	6821      	ldr	r1, [r4, #0]
 8001d10:	4291      	cmp	r1, r2
 8001d12:	d101      	bne.n	8001d18 <HAL_DMA_PollForTransfer+0x2d0>
 8001d14:	2180      	movs	r1, #128	@ 0x80
 8001d16:	e010      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001d18:	4a56      	ldr	r2, [pc, #344]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001d1a:	3228      	adds	r2, #40	@ 0x28
 8001d1c:	6821      	ldr	r1, [r4, #0]
 8001d1e:	4291      	cmp	r1, r2
 8001d20:	d101      	bne.n	8001d26 <HAL_DMA_PollForTransfer+0x2de>
 8001d22:	14c9      	asrs	r1, r1, #19
 8001d24:	e009      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001d26:	4a53      	ldr	r2, [pc, #332]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001d28:	323c      	adds	r2, #60	@ 0x3c
 8001d2a:	6821      	ldr	r1, [r4, #0]
 8001d2c:	4291      	cmp	r1, r2
 8001d2e:	d102      	bne.n	8001d36 <HAL_DMA_PollForTransfer+0x2ee>
 8001d30:	f44f 4100 	mov.w	r1, #32768	@ 0x8000
 8001d34:	e001      	b.n	8001d3a <HAL_DMA_PollForTransfer+0x2f2>
 8001d36:	f44f 2100 	mov.w	r1, #524288	@ 0x80000
 8001d3a:	4008      	ands	r0, r1
 8001d3c:	b198      	cbz	r0, 8001d66 <HAL_DMA_PollForTransfer+0x31e>
 8001d3e:	f894 1040 	ldrb.w	r1, [r4, #64]	@ 0x40
 8001d42:	2001      	movs	r0, #1
 8001d44:	4088      	lsls	r0, r1
 8001d46:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8001d48:	6048      	str	r0, [r1, #4]
 8001d4a:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8001d4c:	f040 0001 	orr.w	r0, r0, #1
 8001d50:	63a0      	str	r0, [r4, #56]	@ 0x38
 8001d52:	2001      	movs	r0, #1
 8001d54:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 8001d58:	bf00      	nop
 8001d5a:	2000      	movs	r0, #0
 8001d5c:	f884 0020 	strb.w	r0, [r4, #32]
 8001d60:	bf00      	nop
 8001d62:	2001      	movs	r0, #1
 8001d64:	e683      	b.n	8001a6e <HAL_DMA_PollForTransfer+0x26>
 8001d66:	1c68      	adds	r0, r5, #1
 8001d68:	b1a0      	cbz	r0, 8001d94 <HAL_DMA_PollForTransfer+0x34c>
 8001d6a:	b12d      	cbz	r5, 8001d78 <HAL_DMA_PollForTransfer+0x330>
 8001d6c:	f001 f984 	bl	8003078 <HAL_GetTick>
 8001d70:	eba0 0008 	sub.w	r0, r0, r8
 8001d74:	42a8      	cmp	r0, r5
 8001d76:	d90d      	bls.n	8001d94 <HAL_DMA_PollForTransfer+0x34c>
 8001d78:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8001d7a:	f040 0020 	orr.w	r0, r0, #32
 8001d7e:	63a0      	str	r0, [r4, #56]	@ 0x38
 8001d80:	2001      	movs	r0, #1
 8001d82:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 8001d86:	bf00      	nop
 8001d88:	2000      	movs	r0, #0
 8001d8a:	f884 0020 	strb.w	r0, [r4, #32]
 8001d8e:	bf00      	nop
 8001d90:	2001      	movs	r0, #1
 8001d92:	e66c      	b.n	8001a6e <HAL_DMA_PollForTransfer+0x26>
 8001d94:	4936      	ldr	r1, [pc, #216]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001d96:	3178      	adds	r1, #120	@ 0x78
 8001d98:	6820      	ldr	r0, [r4, #0]
 8001d9a:	4288      	cmp	r0, r1
 8001d9c:	d904      	bls.n	8001da8 <HAL_DMA_PollForTransfer+0x360>
 8001d9e:	4835      	ldr	r0, [pc, #212]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001da0:	3808      	subs	r0, #8
 8001da2:	6800      	ldr	r0, [r0, #0]
 8001da4:	4038      	ands	r0, r7
 8001da6:	e003      	b.n	8001db0 <HAL_DMA_PollForTransfer+0x368>
 8001da8:	4831      	ldr	r0, [pc, #196]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001daa:	3808      	subs	r0, #8
 8001dac:	6800      	ldr	r0, [r0, #0]
 8001dae:	4038      	ands	r0, r7
 8001db0:	2800      	cmp	r0, #0
 8001db2:	f43f af13 	beq.w	8001bdc <HAL_DMA_PollForTransfer+0x194>
 8001db6:	2e00      	cmp	r6, #0
 8001db8:	d172      	bne.n	8001ea0 <HAL_DMA_PollForTransfer+0x458>
 8001dba:	492d      	ldr	r1, [pc, #180]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001dbc:	3178      	adds	r1, #120	@ 0x78
 8001dbe:	6820      	ldr	r0, [r4, #0]
 8001dc0:	4288      	cmp	r0, r1
 8001dc2:	d959      	bls.n	8001e78 <HAL_DMA_PollForTransfer+0x430>
 8001dc4:	492a      	ldr	r1, [pc, #168]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001dc6:	6820      	ldr	r0, [r4, #0]
 8001dc8:	4288      	cmp	r0, r1
 8001dca:	d101      	bne.n	8001dd0 <HAL_DMA_PollForTransfer+0x388>
 8001dcc:	2002      	movs	r0, #2
 8001dce:	e04a      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001dd0:	4927      	ldr	r1, [pc, #156]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001dd2:	3114      	adds	r1, #20
 8001dd4:	6820      	ldr	r0, [r4, #0]
 8001dd6:	4288      	cmp	r0, r1
 8001dd8:	d101      	bne.n	8001dde <HAL_DMA_PollForTransfer+0x396>
 8001dda:	2020      	movs	r0, #32
 8001ddc:	e043      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001dde:	4924      	ldr	r1, [pc, #144]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001de0:	3128      	adds	r1, #40	@ 0x28
 8001de2:	6820      	ldr	r0, [r4, #0]
 8001de4:	4288      	cmp	r0, r1
 8001de6:	d101      	bne.n	8001dec <HAL_DMA_PollForTransfer+0x3a4>
 8001de8:	1540      	asrs	r0, r0, #21
 8001dea:	e03c      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001dec:	4920      	ldr	r1, [pc, #128]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001dee:	313c      	adds	r1, #60	@ 0x3c
 8001df0:	6820      	ldr	r0, [r4, #0]
 8001df2:	4288      	cmp	r0, r1
 8001df4:	d102      	bne.n	8001dfc <HAL_DMA_PollForTransfer+0x3b4>
 8001df6:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001dfa:	e034      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001dfc:	491c      	ldr	r1, [pc, #112]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001dfe:	3150      	adds	r1, #80	@ 0x50
 8001e00:	6820      	ldr	r0, [r4, #0]
 8001e02:	4288      	cmp	r0, r1
 8001e04:	d102      	bne.n	8001e0c <HAL_DMA_PollForTransfer+0x3c4>
 8001e06:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 8001e0a:	e02c      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001e0c:	4918      	ldr	r1, [pc, #96]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001e0e:	3164      	adds	r1, #100	@ 0x64
 8001e10:	6820      	ldr	r0, [r4, #0]
 8001e12:	4288      	cmp	r0, r1
 8001e14:	d102      	bne.n	8001e1c <HAL_DMA_PollForTransfer+0x3d4>
 8001e16:	f44f 1000 	mov.w	r0, #2097152	@ 0x200000
 8001e1a:	e024      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001e1c:	4914      	ldr	r1, [pc, #80]	@ (8001e70 <HAL_DMA_PollForTransfer+0x428>)
 8001e1e:	3178      	adds	r1, #120	@ 0x78
 8001e20:	6820      	ldr	r0, [r4, #0]
 8001e22:	4288      	cmp	r0, r1
 8001e24:	d101      	bne.n	8001e2a <HAL_DMA_PollForTransfer+0x3e2>
 8001e26:	0480      	lsls	r0, r0, #18
 8001e28:	e01d      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001e2a:	4912      	ldr	r1, [pc, #72]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001e2c:	6820      	ldr	r0, [r4, #0]
 8001e2e:	4288      	cmp	r0, r1
 8001e30:	d101      	bne.n	8001e36 <HAL_DMA_PollForTransfer+0x3ee>
 8001e32:	2002      	movs	r0, #2
 8001e34:	e017      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001e36:	490f      	ldr	r1, [pc, #60]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001e38:	3114      	adds	r1, #20
 8001e3a:	6820      	ldr	r0, [r4, #0]
 8001e3c:	4288      	cmp	r0, r1
 8001e3e:	d101      	bne.n	8001e44 <HAL_DMA_PollForTransfer+0x3fc>
 8001e40:	2020      	movs	r0, #32
 8001e42:	e010      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001e44:	490b      	ldr	r1, [pc, #44]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001e46:	3128      	adds	r1, #40	@ 0x28
 8001e48:	6820      	ldr	r0, [r4, #0]
 8001e4a:	4288      	cmp	r0, r1
 8001e4c:	d101      	bne.n	8001e52 <HAL_DMA_PollForTransfer+0x40a>
 8001e4e:	1540      	asrs	r0, r0, #21
 8001e50:	e009      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001e52:	4908      	ldr	r1, [pc, #32]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001e54:	313c      	adds	r1, #60	@ 0x3c
 8001e56:	6820      	ldr	r0, [r4, #0]
 8001e58:	4288      	cmp	r0, r1
 8001e5a:	d102      	bne.n	8001e62 <HAL_DMA_PollForTransfer+0x41a>
 8001e5c:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001e60:	e001      	b.n	8001e66 <HAL_DMA_PollForTransfer+0x41e>
 8001e62:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 8001e66:	4903      	ldr	r1, [pc, #12]	@ (8001e74 <HAL_DMA_PollForTransfer+0x42c>)
 8001e68:	1f09      	subs	r1, r1, #4
 8001e6a:	6008      	str	r0, [r1, #0]
 8001e6c:	e059      	b.n	8001f22 <HAL_DMA_PollForTransfer+0x4da>
 8001e6e:	0000      	.short	0x0000
 8001e70:	40020008 	.word	0x40020008
 8001e74:	40020408 	.word	0x40020408
 8001e78:	4986      	ldr	r1, [pc, #536]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001e7a:	6820      	ldr	r0, [r4, #0]
 8001e7c:	4288      	cmp	r0, r1
 8001e7e:	d101      	bne.n	8001e84 <HAL_DMA_PollForTransfer+0x43c>
 8001e80:	2002      	movs	r0, #2
 8001e82:	e04b      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001e84:	4983      	ldr	r1, [pc, #524]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001e86:	3114      	adds	r1, #20
 8001e88:	6820      	ldr	r0, [r4, #0]
 8001e8a:	4288      	cmp	r0, r1
 8001e8c:	d101      	bne.n	8001e92 <HAL_DMA_PollForTransfer+0x44a>
 8001e8e:	2020      	movs	r0, #32
 8001e90:	e044      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001e92:	4980      	ldr	r1, [pc, #512]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001e94:	3128      	adds	r1, #40	@ 0x28
 8001e96:	6820      	ldr	r0, [r4, #0]
 8001e98:	4288      	cmp	r0, r1
 8001e9a:	d102      	bne.n	8001ea2 <HAL_DMA_PollForTransfer+0x45a>
 8001e9c:	1540      	asrs	r0, r0, #21
 8001e9e:	e03d      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001ea0:	e043      	b.n	8001f2a <HAL_DMA_PollForTransfer+0x4e2>
 8001ea2:	497c      	ldr	r1, [pc, #496]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001ea4:	313c      	adds	r1, #60	@ 0x3c
 8001ea6:	6820      	ldr	r0, [r4, #0]
 8001ea8:	4288      	cmp	r0, r1
 8001eaa:	d102      	bne.n	8001eb2 <HAL_DMA_PollForTransfer+0x46a>
 8001eac:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001eb0:	e034      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001eb2:	4978      	ldr	r1, [pc, #480]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001eb4:	3150      	adds	r1, #80	@ 0x50
 8001eb6:	6820      	ldr	r0, [r4, #0]
 8001eb8:	4288      	cmp	r0, r1
 8001eba:	d102      	bne.n	8001ec2 <HAL_DMA_PollForTransfer+0x47a>
 8001ebc:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 8001ec0:	e02c      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001ec2:	4974      	ldr	r1, [pc, #464]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001ec4:	3164      	adds	r1, #100	@ 0x64
 8001ec6:	6820      	ldr	r0, [r4, #0]
 8001ec8:	4288      	cmp	r0, r1
 8001eca:	d102      	bne.n	8001ed2 <HAL_DMA_PollForTransfer+0x48a>
 8001ecc:	f44f 1000 	mov.w	r0, #2097152	@ 0x200000
 8001ed0:	e024      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001ed2:	4970      	ldr	r1, [pc, #448]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001ed4:	3178      	adds	r1, #120	@ 0x78
 8001ed6:	6820      	ldr	r0, [r4, #0]
 8001ed8:	4288      	cmp	r0, r1
 8001eda:	d101      	bne.n	8001ee0 <HAL_DMA_PollForTransfer+0x498>
 8001edc:	0480      	lsls	r0, r0, #18
 8001ede:	e01d      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001ee0:	496d      	ldr	r1, [pc, #436]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001ee2:	6820      	ldr	r0, [r4, #0]
 8001ee4:	4288      	cmp	r0, r1
 8001ee6:	d101      	bne.n	8001eec <HAL_DMA_PollForTransfer+0x4a4>
 8001ee8:	2002      	movs	r0, #2
 8001eea:	e017      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001eec:	496a      	ldr	r1, [pc, #424]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001eee:	3114      	adds	r1, #20
 8001ef0:	6820      	ldr	r0, [r4, #0]
 8001ef2:	4288      	cmp	r0, r1
 8001ef4:	d101      	bne.n	8001efa <HAL_DMA_PollForTransfer+0x4b2>
 8001ef6:	2020      	movs	r0, #32
 8001ef8:	e010      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001efa:	4967      	ldr	r1, [pc, #412]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001efc:	3128      	adds	r1, #40	@ 0x28
 8001efe:	6820      	ldr	r0, [r4, #0]
 8001f00:	4288      	cmp	r0, r1
 8001f02:	d101      	bne.n	8001f08 <HAL_DMA_PollForTransfer+0x4c0>
 8001f04:	1540      	asrs	r0, r0, #21
 8001f06:	e009      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001f08:	4963      	ldr	r1, [pc, #396]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001f0a:	313c      	adds	r1, #60	@ 0x3c
 8001f0c:	6820      	ldr	r0, [r4, #0]
 8001f0e:	4288      	cmp	r0, r1
 8001f10:	d102      	bne.n	8001f18 <HAL_DMA_PollForTransfer+0x4d0>
 8001f12:	f44f 5000 	mov.w	r0, #8192	@ 0x2000
 8001f16:	e001      	b.n	8001f1c <HAL_DMA_PollForTransfer+0x4d4>
 8001f18:	f44f 3000 	mov.w	r0, #131072	@ 0x20000
 8001f1c:	495d      	ldr	r1, [pc, #372]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f1e:	3908      	subs	r1, #8
 8001f20:	6048      	str	r0, [r1, #4]
 8001f22:	2001      	movs	r0, #1
 8001f24:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 8001f28:	e0ad      	b.n	8002086 <HAL_DMA_PollForTransfer+0x63e>
 8001f2a:	495a      	ldr	r1, [pc, #360]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f2c:	3178      	adds	r1, #120	@ 0x78
 8001f2e:	6820      	ldr	r0, [r4, #0]
 8001f30:	4288      	cmp	r0, r1
 8001f32:	d954      	bls.n	8001fde <HAL_DMA_PollForTransfer+0x596>
 8001f34:	4957      	ldr	r1, [pc, #348]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f36:	6820      	ldr	r0, [r4, #0]
 8001f38:	4288      	cmp	r0, r1
 8001f3a:	d101      	bne.n	8001f40 <HAL_DMA_PollForTransfer+0x4f8>
 8001f3c:	2004      	movs	r0, #4
 8001f3e:	e04a      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001f40:	4954      	ldr	r1, [pc, #336]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f42:	3114      	adds	r1, #20
 8001f44:	6820      	ldr	r0, [r4, #0]
 8001f46:	4288      	cmp	r0, r1
 8001f48:	d101      	bne.n	8001f4e <HAL_DMA_PollForTransfer+0x506>
 8001f4a:	2040      	movs	r0, #64	@ 0x40
 8001f4c:	e043      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001f4e:	4951      	ldr	r1, [pc, #324]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f50:	3128      	adds	r1, #40	@ 0x28
 8001f52:	6820      	ldr	r0, [r4, #0]
 8001f54:	4288      	cmp	r0, r1
 8001f56:	d101      	bne.n	8001f5c <HAL_DMA_PollForTransfer+0x514>
 8001f58:	1500      	asrs	r0, r0, #20
 8001f5a:	e03c      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001f5c:	494d      	ldr	r1, [pc, #308]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f5e:	313c      	adds	r1, #60	@ 0x3c
 8001f60:	6820      	ldr	r0, [r4, #0]
 8001f62:	4288      	cmp	r0, r1
 8001f64:	d102      	bne.n	8001f6c <HAL_DMA_PollForTransfer+0x524>
 8001f66:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 8001f6a:	e034      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001f6c:	4949      	ldr	r1, [pc, #292]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f6e:	3150      	adds	r1, #80	@ 0x50
 8001f70:	6820      	ldr	r0, [r4, #0]
 8001f72:	4288      	cmp	r0, r1
 8001f74:	d102      	bne.n	8001f7c <HAL_DMA_PollForTransfer+0x534>
 8001f76:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8001f7a:	e02c      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001f7c:	4945      	ldr	r1, [pc, #276]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f7e:	3164      	adds	r1, #100	@ 0x64
 8001f80:	6820      	ldr	r0, [r4, #0]
 8001f82:	4288      	cmp	r0, r1
 8001f84:	d102      	bne.n	8001f8c <HAL_DMA_PollForTransfer+0x544>
 8001f86:	f44f 0080 	mov.w	r0, #4194304	@ 0x400000
 8001f8a:	e024      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001f8c:	4941      	ldr	r1, [pc, #260]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001f8e:	3178      	adds	r1, #120	@ 0x78
 8001f90:	6820      	ldr	r0, [r4, #0]
 8001f92:	4288      	cmp	r0, r1
 8001f94:	d101      	bne.n	8001f9a <HAL_DMA_PollForTransfer+0x552>
 8001f96:	04c0      	lsls	r0, r0, #19
 8001f98:	e01d      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001f9a:	493f      	ldr	r1, [pc, #252]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001f9c:	6820      	ldr	r0, [r4, #0]
 8001f9e:	4288      	cmp	r0, r1
 8001fa0:	d101      	bne.n	8001fa6 <HAL_DMA_PollForTransfer+0x55e>
 8001fa2:	2004      	movs	r0, #4
 8001fa4:	e017      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001fa6:	493c      	ldr	r1, [pc, #240]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001fa8:	3114      	adds	r1, #20
 8001faa:	6820      	ldr	r0, [r4, #0]
 8001fac:	4288      	cmp	r0, r1
 8001fae:	d101      	bne.n	8001fb4 <HAL_DMA_PollForTransfer+0x56c>
 8001fb0:	2040      	movs	r0, #64	@ 0x40
 8001fb2:	e010      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001fb4:	4938      	ldr	r1, [pc, #224]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001fb6:	3128      	adds	r1, #40	@ 0x28
 8001fb8:	6820      	ldr	r0, [r4, #0]
 8001fba:	4288      	cmp	r0, r1
 8001fbc:	d101      	bne.n	8001fc2 <HAL_DMA_PollForTransfer+0x57a>
 8001fbe:	1500      	asrs	r0, r0, #20
 8001fc0:	e009      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001fc2:	4935      	ldr	r1, [pc, #212]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001fc4:	313c      	adds	r1, #60	@ 0x3c
 8001fc6:	6820      	ldr	r0, [r4, #0]
 8001fc8:	4288      	cmp	r0, r1
 8001fca:	d102      	bne.n	8001fd2 <HAL_DMA_PollForTransfer+0x58a>
 8001fcc:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 8001fd0:	e001      	b.n	8001fd6 <HAL_DMA_PollForTransfer+0x58e>
 8001fd2:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8001fd6:	4930      	ldr	r1, [pc, #192]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8001fd8:	1f09      	subs	r1, r1, #4
 8001fda:	6008      	str	r0, [r1, #0]
 8001fdc:	e053      	b.n	8002086 <HAL_DMA_PollForTransfer+0x63e>
 8001fde:	492d      	ldr	r1, [pc, #180]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001fe0:	6820      	ldr	r0, [r4, #0]
 8001fe2:	4288      	cmp	r0, r1
 8001fe4:	d101      	bne.n	8001fea <HAL_DMA_PollForTransfer+0x5a2>
 8001fe6:	2004      	movs	r0, #4
 8001fe8:	e04a      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8001fea:	492a      	ldr	r1, [pc, #168]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001fec:	3114      	adds	r1, #20
 8001fee:	6820      	ldr	r0, [r4, #0]
 8001ff0:	4288      	cmp	r0, r1
 8001ff2:	d101      	bne.n	8001ff8 <HAL_DMA_PollForTransfer+0x5b0>
 8001ff4:	2040      	movs	r0, #64	@ 0x40
 8001ff6:	e043      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8001ff8:	4926      	ldr	r1, [pc, #152]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8001ffa:	3128      	adds	r1, #40	@ 0x28
 8001ffc:	6820      	ldr	r0, [r4, #0]
 8001ffe:	4288      	cmp	r0, r1
 8002000:	d101      	bne.n	8002006 <HAL_DMA_PollForTransfer+0x5be>
 8002002:	1500      	asrs	r0, r0, #20
 8002004:	e03c      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8002006:	4923      	ldr	r1, [pc, #140]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8002008:	313c      	adds	r1, #60	@ 0x3c
 800200a:	6820      	ldr	r0, [r4, #0]
 800200c:	4288      	cmp	r0, r1
 800200e:	d102      	bne.n	8002016 <HAL_DMA_PollForTransfer+0x5ce>
 8002010:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 8002014:	e034      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8002016:	491f      	ldr	r1, [pc, #124]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8002018:	3150      	adds	r1, #80	@ 0x50
 800201a:	6820      	ldr	r0, [r4, #0]
 800201c:	4288      	cmp	r0, r1
 800201e:	d102      	bne.n	8002026 <HAL_DMA_PollForTransfer+0x5de>
 8002020:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8002024:	e02c      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8002026:	491b      	ldr	r1, [pc, #108]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8002028:	3164      	adds	r1, #100	@ 0x64
 800202a:	6820      	ldr	r0, [r4, #0]
 800202c:	4288      	cmp	r0, r1
 800202e:	d102      	bne.n	8002036 <HAL_DMA_PollForTransfer+0x5ee>
 8002030:	f44f 0080 	mov.w	r0, #4194304	@ 0x400000
 8002034:	e024      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8002036:	4917      	ldr	r1, [pc, #92]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8002038:	3178      	adds	r1, #120	@ 0x78
 800203a:	6820      	ldr	r0, [r4, #0]
 800203c:	4288      	cmp	r0, r1
 800203e:	d101      	bne.n	8002044 <HAL_DMA_PollForTransfer+0x5fc>
 8002040:	04c0      	lsls	r0, r0, #19
 8002042:	e01d      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8002044:	4914      	ldr	r1, [pc, #80]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8002046:	6820      	ldr	r0, [r4, #0]
 8002048:	4288      	cmp	r0, r1
 800204a:	d101      	bne.n	8002050 <HAL_DMA_PollForTransfer+0x608>
 800204c:	2004      	movs	r0, #4
 800204e:	e017      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 8002050:	4911      	ldr	r1, [pc, #68]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8002052:	3114      	adds	r1, #20
 8002054:	6820      	ldr	r0, [r4, #0]
 8002056:	4288      	cmp	r0, r1
 8002058:	d101      	bne.n	800205e <HAL_DMA_PollForTransfer+0x616>
 800205a:	2040      	movs	r0, #64	@ 0x40
 800205c:	e010      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 800205e:	490e      	ldr	r1, [pc, #56]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 8002060:	3128      	adds	r1, #40	@ 0x28
 8002062:	6820      	ldr	r0, [r4, #0]
 8002064:	4288      	cmp	r0, r1
 8002066:	d101      	bne.n	800206c <HAL_DMA_PollForTransfer+0x624>
 8002068:	1500      	asrs	r0, r0, #20
 800206a:	e009      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 800206c:	490a      	ldr	r1, [pc, #40]	@ (8002098 <HAL_DMA_PollForTransfer+0x650>)
 800206e:	313c      	adds	r1, #60	@ 0x3c
 8002070:	6820      	ldr	r0, [r4, #0]
 8002072:	4288      	cmp	r0, r1
 8002074:	d102      	bne.n	800207c <HAL_DMA_PollForTransfer+0x634>
 8002076:	f44f 4080 	mov.w	r0, #16384	@ 0x4000
 800207a:	e001      	b.n	8002080 <HAL_DMA_PollForTransfer+0x638>
 800207c:	f44f 2080 	mov.w	r0, #262144	@ 0x40000
 8002080:	4904      	ldr	r1, [pc, #16]	@ (8002094 <HAL_DMA_PollForTransfer+0x64c>)
 8002082:	3908      	subs	r1, #8
 8002084:	6048      	str	r0, [r1, #4]
 8002086:	bf00      	nop
 8002088:	2000      	movs	r0, #0
 800208a:	f884 0020 	strb.w	r0, [r4, #32]
 800208e:	bf00      	nop
 8002090:	bf00      	nop
 8002092:	e4ec      	b.n	8001a6e <HAL_DMA_PollForTransfer+0x26>
 8002094:	40020008 	.word	0x40020008
 8002098:	40020408 	.word	0x40020408

0800209c <HAL_DMA_RegisterCallback>:
 800209c:	b510      	push	{r4, lr}
 800209e:	4603      	mov	r3, r0
 80020a0:	2400      	movs	r4, #0
 80020a2:	bf00      	nop
 80020a4:	f893 0020 	ldrb.w	r0, [r3, #32]
 80020a8:	2801      	cmp	r0, #1
 80020aa:	d101      	bne.n	80020b0 <HAL_DMA_RegisterCallback+0x14>
 80020ac:	2002      	movs	r0, #2
 80020ae:	bd10      	pop	{r4, pc}
 80020b0:	2001      	movs	r0, #1
 80020b2:	f883 0020 	strb.w	r0, [r3, #32]
 80020b6:	bf00      	nop
 80020b8:	f893 0021 	ldrb.w	r0, [r3, #33]	@ 0x21
 80020bc:	2801      	cmp	r0, #1
 80020be:	d112      	bne.n	80020e6 <HAL_DMA_RegisterCallback+0x4a>
 80020c0:	b131      	cbz	r1, 80020d0 <HAL_DMA_RegisterCallback+0x34>
 80020c2:	2901      	cmp	r1, #1
 80020c4:	d006      	beq.n	80020d4 <HAL_DMA_RegisterCallback+0x38>
 80020c6:	2902      	cmp	r1, #2
 80020c8:	d006      	beq.n	80020d8 <HAL_DMA_RegisterCallback+0x3c>
 80020ca:	2903      	cmp	r1, #3
 80020cc:	d108      	bne.n	80020e0 <HAL_DMA_RegisterCallback+0x44>
 80020ce:	e005      	b.n	80020dc <HAL_DMA_RegisterCallback+0x40>
 80020d0:	629a      	str	r2, [r3, #40]	@ 0x28
 80020d2:	e007      	b.n	80020e4 <HAL_DMA_RegisterCallback+0x48>
 80020d4:	62da      	str	r2, [r3, #44]	@ 0x2c
 80020d6:	e005      	b.n	80020e4 <HAL_DMA_RegisterCallback+0x48>
 80020d8:	631a      	str	r2, [r3, #48]	@ 0x30
 80020da:	e003      	b.n	80020e4 <HAL_DMA_RegisterCallback+0x48>
 80020dc:	635a      	str	r2, [r3, #52]	@ 0x34
 80020de:	e001      	b.n	80020e4 <HAL_DMA_RegisterCallback+0x48>
 80020e0:	2401      	movs	r4, #1
 80020e2:	bf00      	nop
 80020e4:	e000      	b.n	80020e8 <HAL_DMA_RegisterCallback+0x4c>
 80020e6:	2401      	movs	r4, #1
 80020e8:	bf00      	nop
 80020ea:	2000      	movs	r0, #0
 80020ec:	f883 0020 	strb.w	r0, [r3, #32]
 80020f0:	bf00      	nop
 80020f2:	4620      	mov	r0, r4
 80020f4:	e7db      	b.n	80020ae <HAL_DMA_RegisterCallback+0x12>

080020f6 <HAL_DMA_Start>:
 80020f6:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 80020fa:	4604      	mov	r4, r0
 80020fc:	460d      	mov	r5, r1
 80020fe:	4616      	mov	r6, r2
 8002100:	461f      	mov	r7, r3
 8002102:	f04f 0800 	mov.w	r8, #0
 8002106:	bf00      	nop
 8002108:	f894 0020 	ldrb.w	r0, [r4, #32]
 800210c:	2801      	cmp	r0, #1
 800210e:	d102      	bne.n	8002116 <HAL_DMA_Start+0x20>
 8002110:	2002      	movs	r0, #2
 8002112:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
 8002116:	2001      	movs	r0, #1
 8002118:	f884 0020 	strb.w	r0, [r4, #32]
 800211c:	bf00      	nop
 800211e:	f894 0021 	ldrb.w	r0, [r4, #33]	@ 0x21
 8002122:	2801      	cmp	r0, #1
 8002124:	d117      	bne.n	8002156 <HAL_DMA_Start+0x60>
 8002126:	2002      	movs	r0, #2
 8002128:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 800212c:	2000      	movs	r0, #0
 800212e:	63a0      	str	r0, [r4, #56]	@ 0x38
 8002130:	6820      	ldr	r0, [r4, #0]
 8002132:	6800      	ldr	r0, [r0, #0]
 8002134:	f020 0001 	bic.w	r0, r0, #1
 8002138:	6821      	ldr	r1, [r4, #0]
 800213a:	6008      	str	r0, [r1, #0]
 800213c:	463b      	mov	r3, r7
 800213e:	4632      	mov	r2, r6
 8002140:	4629      	mov	r1, r5
 8002142:	4620      	mov	r0, r4
 8002144:	f7fe fe84 	bl	8000e50 <DMA_SetConfig>
 8002148:	6820      	ldr	r0, [r4, #0]
 800214a:	6800      	ldr	r0, [r0, #0]
 800214c:	f040 0001 	orr.w	r0, r0, #1
 8002150:	6821      	ldr	r1, [r4, #0]
 8002152:	6008      	str	r0, [r1, #0]
 8002154:	e006      	b.n	8002164 <HAL_DMA_Start+0x6e>
 8002156:	bf00      	nop
 8002158:	2000      	movs	r0, #0
 800215a:	f884 0020 	strb.w	r0, [r4, #32]
 800215e:	bf00      	nop
 8002160:	f04f 0802 	mov.w	r8, #2
 8002164:	4640      	mov	r0, r8
 8002166:	e7d4      	b.n	8002112 <HAL_DMA_Start+0x1c>

08002168 <HAL_DMA_Start_IT>:
 8002168:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 800216c:	4604      	mov	r4, r0
 800216e:	460d      	mov	r5, r1
 8002170:	4616      	mov	r6, r2
 8002172:	461f      	mov	r7, r3
 8002174:	f04f 0800 	mov.w	r8, #0
 8002178:	bf00      	nop
 800217a:	f894 0020 	ldrb.w	r0, [r4, #32]
 800217e:	2801      	cmp	r0, #1
 8002180:	d102      	bne.n	8002188 <HAL_DMA_Start_IT+0x20>
 8002182:	2002      	movs	r0, #2
 8002184:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
 8002188:	2001      	movs	r0, #1
 800218a:	f884 0020 	strb.w	r0, [r4, #32]
 800218e:	bf00      	nop
 8002190:	f894 0021 	ldrb.w	r0, [r4, #33]	@ 0x21
 8002194:	2801      	cmp	r0, #1
 8002196:	d12c      	bne.n	80021f2 <HAL_DMA_Start_IT+0x8a>
 8002198:	2002      	movs	r0, #2
 800219a:	f884 0021 	strb.w	r0, [r4, #33]	@ 0x21
 800219e:	2000      	movs	r0, #0
 80021a0:	63a0      	str	r0, [r4, #56]	@ 0x38
 80021a2:	6820      	ldr	r0, [r4, #0]
 80021a4:	6800      	ldr	r0, [r0, #0]
 80021a6:	f020 0001 	bic.w	r0, r0, #1
 80021aa:	6821      	ldr	r1, [r4, #0]
 80021ac:	6008      	str	r0, [r1, #0]
 80021ae:	463b      	mov	r3, r7
 80021b0:	4632      	mov	r2, r6
 80021b2:	4629      	mov	r1, r5
 80021b4:	4620      	mov	r0, r4
 80021b6:	f7fe fe4b 	bl	8000e50 <DMA_SetConfig>
 80021ba:	6ae0      	ldr	r0, [r4, #44]	@ 0x2c
 80021bc:	b130      	cbz	r0, 80021cc <HAL_DMA_Start_IT+0x64>
 80021be:	6820      	ldr	r0, [r4, #0]
 80021c0:	6800      	ldr	r0, [r0, #0]
 80021c2:	f040 000e 	orr.w	r0, r0, #14
 80021c6:	6821      	ldr	r1, [r4, #0]
 80021c8:	6008      	str	r0, [r1, #0]
 80021ca:	e00b      	b.n	80021e4 <HAL_DMA_Start_IT+0x7c>
 80021cc:	6820      	ldr	r0, [r4, #0]
 80021ce:	6800      	ldr	r0, [r0, #0]
 80021d0:	f020 0004 	bic.w	r0, r0, #4
 80021d4:	6821      	ldr	r1, [r4, #0]
 80021d6:	6008      	str	r0, [r1, #0]
 80021d8:	6820      	ldr	r0, [r4, #0]
 80021da:	6800      	ldr	r0, [r0, #0]
 80021dc:	f040 000a 	orr.w	r0, r0, #10
 80021e0:	6821      	ldr	r1, [r4, #0]
 80021e2:	6008      	str	r0, [r1, #0]
 80021e4:	6820      	ldr	r0, [r4, #0]
 80021e6:	6800      	ldr	r0, [r0, #0]
 80021e8:	f040 0001 	orr.w	r0, r0, #1
 80021ec:	6821      	ldr	r1, [r4, #0]
 80021ee:	6008      	str	r0, [r1, #0]
 80021f0:	e006      	b.n	8002200 <HAL_DMA_Start_IT+0x98>
 80021f2:	bf00      	nop
 80021f4:	2000      	movs	r0, #0
 80021f6:	f884 0020 	strb.w	r0, [r4, #32]
 80021fa:	bf00      	nop
 80021fc:	f04f 0802 	mov.w	r8, #2
 8002200:	4640      	mov	r0, r8
 8002202:	e7bf      	b.n	8002184 <HAL_DMA_Start_IT+0x1c>

08002204 <HAL_DMA_UnRegisterCallback>:
 8002204:	4602      	mov	r2, r0
 8002206:	2300      	movs	r3, #0
 8002208:	bf00      	nop
 800220a:	f892 0020 	ldrb.w	r0, [r2, #32]
 800220e:	2801      	cmp	r0, #1
 8002210:	d101      	bne.n	8002216 <HAL_DMA_UnRegisterCallback+0x12>
 8002212:	2002      	movs	r0, #2
 8002214:	4770      	bx	lr
 8002216:	2001      	movs	r0, #1
 8002218:	f882 0020 	strb.w	r0, [r2, #32]
 800221c:	bf00      	nop
 800221e:	f892 0021 	ldrb.w	r0, [r2, #33]	@ 0x21
 8002222:	2801      	cmp	r0, #1
 8002224:	d11b      	bne.n	800225e <HAL_DMA_UnRegisterCallback+0x5a>
 8002226:	2905      	cmp	r1, #5
 8002228:	d216      	bcs.n	8002258 <HAL_DMA_UnRegisterCallback+0x54>
 800222a:	e8df f001 	tbb	[pc, r1]
 800222e:	0603      	.short	0x0603
 8002230:	000f0c09 	.word	0x000f0c09
 8002234:	2000      	movs	r0, #0
 8002236:	6290      	str	r0, [r2, #40]	@ 0x28
 8002238:	e010      	b.n	800225c <HAL_DMA_UnRegisterCallback+0x58>
 800223a:	2000      	movs	r0, #0
 800223c:	62d0      	str	r0, [r2, #44]	@ 0x2c
 800223e:	e00d      	b.n	800225c <HAL_DMA_UnRegisterCallback+0x58>
 8002240:	2000      	movs	r0, #0
 8002242:	6310      	str	r0, [r2, #48]	@ 0x30
 8002244:	e00a      	b.n	800225c <HAL_DMA_UnRegisterCallback+0x58>
 8002246:	2000      	movs	r0, #0
 8002248:	6350      	str	r0, [r2, #52]	@ 0x34
 800224a:	e007      	b.n	800225c <HAL_DMA_UnRegisterCallback+0x58>
 800224c:	2000      	movs	r0, #0
 800224e:	6290      	str	r0, [r2, #40]	@ 0x28
 8002250:	62d0      	str	r0, [r2, #44]	@ 0x2c
 8002252:	6310      	str	r0, [r2, #48]	@ 0x30
 8002254:	6350      	str	r0, [r2, #52]	@ 0x34
 8002256:	e001      	b.n	800225c <HAL_DMA_UnRegisterCallback+0x58>
 8002258:	2301      	movs	r3, #1
 800225a:	bf00      	nop
 800225c:	e000      	b.n	8002260 <HAL_DMA_UnRegisterCallback+0x5c>
 800225e:	2301      	movs	r3, #1
 8002260:	bf00      	nop
 8002262:	2000      	movs	r0, #0
 8002264:	f882 0020 	strb.w	r0, [r2, #32]
 8002268:	bf00      	nop
 800226a:	4618      	mov	r0, r3
 800226c:	e7d2      	b.n	8002214 <HAL_DMA_UnRegisterCallback+0x10>
	...

08002270 <HAL_DeInit>:
 8002270:	b510      	push	{r4, lr}
 8002272:	f04f 30ff 	mov.w	r0, #4294967295
 8002276:	4906      	ldr	r1, [pc, #24]	@ (8002290 <HAL_DeInit+0x20>)
 8002278:	6108      	str	r0, [r1, #16]
 800227a:	2000      	movs	r0, #0
 800227c:	6108      	str	r0, [r1, #16]
 800227e:	1e40      	subs	r0, r0, #1
 8002280:	60c8      	str	r0, [r1, #12]
 8002282:	2000      	movs	r0, #0
 8002284:	60c8      	str	r0, [r1, #12]
 8002286:	f001 f854 	bl	8003332 <HAL_MspDeInit>
 800228a:	2000      	movs	r0, #0
 800228c:	bd10      	pop	{r4, pc}
 800228e:	0000      	.short	0x0000
 8002290:	40021000 	.word	0x40021000

08002294 <HAL_Delay>:
 8002294:	b570      	push	{r4, r5, r6, lr}
 8002296:	4604      	mov	r4, r0
 8002298:	f000 feee 	bl	8003078 <HAL_GetTick>
 800229c:	4606      	mov	r6, r0
 800229e:	4625      	mov	r5, r4
 80022a0:	1c68      	adds	r0, r5, #1
 80022a2:	b110      	cbz	r0, 80022aa <HAL_Delay+0x16>
 80022a4:	4804      	ldr	r0, [pc, #16]	@ (80022b8 <HAL_Delay+0x24>)
 80022a6:	7800      	ldrb	r0, [r0, #0]
 80022a8:	4405      	add	r5, r0
 80022aa:	bf00      	nop
 80022ac:	f000 fee4 	bl	8003078 <HAL_GetTick>
 80022b0:	1b80      	subs	r0, r0, r6
 80022b2:	42a8      	cmp	r0, r5
 80022b4:	d3fa      	bcc.n	80022ac <HAL_Delay+0x18>
 80022b6:	bd70      	pop	{r4, r5, r6, pc}
 80022b8:	20000014 	.word	0x20000014

080022bc <HAL_EXTI_ClearConfigLine>:
 80022bc:	b530      	push	{r4, r5, lr}
 80022be:	4601      	mov	r1, r0
 80022c0:	b909      	cbnz	r1, 80022c6 <HAL_EXTI_ClearConfigLine+0xa>
 80022c2:	2001      	movs	r0, #1
 80022c4:	bd30      	pop	{r4, r5, pc}
 80022c6:	7808      	ldrb	r0, [r1, #0]
 80022c8:	f000 021f 	and.w	r2, r0, #31
 80022cc:	2001      	movs	r0, #1
 80022ce:	fa00 f302 	lsl.w	r3, r0, r2
 80022d2:	4816      	ldr	r0, [pc, #88]	@ (800232c <HAL_EXTI_ClearConfigLine+0x70>)
 80022d4:	6800      	ldr	r0, [r0, #0]
 80022d6:	4398      	bics	r0, r3
 80022d8:	4d14      	ldr	r5, [pc, #80]	@ (800232c <HAL_EXTI_ClearConfigLine+0x70>)
 80022da:	6028      	str	r0, [r5, #0]
 80022dc:	1d28      	adds	r0, r5, #4
 80022de:	6800      	ldr	r0, [r0, #0]
 80022e0:	4398      	bics	r0, r3
 80022e2:	1d2d      	adds	r5, r5, #4
 80022e4:	6028      	str	r0, [r5, #0]
 80022e6:	6808      	ldr	r0, [r1, #0]
 80022e8:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 80022ec:	b1e0      	cbz	r0, 8002328 <HAL_EXTI_ClearConfigLine+0x6c>
 80022ee:	1d28      	adds	r0, r5, #4
 80022f0:	6800      	ldr	r0, [r0, #0]
 80022f2:	4398      	bics	r0, r3
 80022f4:	1d2d      	adds	r5, r5, #4
 80022f6:	6028      	str	r0, [r5, #0]
 80022f8:	1d28      	adds	r0, r5, #4
 80022fa:	6800      	ldr	r0, [r0, #0]
 80022fc:	4398      	bics	r0, r3
 80022fe:	1d2d      	adds	r5, r5, #4
 8002300:	6028      	str	r0, [r5, #0]
 8002302:	6808      	ldr	r0, [r1, #0]
 8002304:	f000 60c0 	and.w	r0, r0, #100663296	@ 0x6000000
 8002308:	f1b0 6fc0 	cmp.w	r0, #100663296	@ 0x6000000
 800230c:	d10c      	bne.n	8002328 <HAL_EXTI_ClearConfigLine+0x6c>
 800230e:	4808      	ldr	r0, [pc, #32]	@ (8002330 <HAL_EXTI_ClearConfigLine+0x74>)
 8002310:	0895      	lsrs	r5, r2, #2
 8002312:	f850 4025 	ldr.w	r4, [r0, r5, lsl #2]
 8002316:	0790      	lsls	r0, r2, #30
 8002318:	0f05      	lsrs	r5, r0, #28
 800231a:	200f      	movs	r0, #15
 800231c:	40a8      	lsls	r0, r5
 800231e:	4384      	bics	r4, r0
 8002320:	4803      	ldr	r0, [pc, #12]	@ (8002330 <HAL_EXTI_ClearConfigLine+0x74>)
 8002322:	0895      	lsrs	r5, r2, #2
 8002324:	f840 4025 	str.w	r4, [r0, r5, lsl #2]
 8002328:	2000      	movs	r0, #0
 800232a:	e7cb      	b.n	80022c4 <HAL_EXTI_ClearConfigLine+0x8>
 800232c:	40010400 	.word	0x40010400
 8002330:	40010008 	.word	0x40010008

08002334 <HAL_EXTI_ClearPending>:
 8002334:	b510      	push	{r4, lr}
 8002336:	460a      	mov	r2, r1
 8002338:	7803      	ldrb	r3, [r0, #0]
 800233a:	f003 041f 	and.w	r4, r3, #31
 800233e:	2301      	movs	r3, #1
 8002340:	fa03 f104 	lsl.w	r1, r3, r4
 8002344:	4b01      	ldr	r3, [pc, #4]	@ (800234c <HAL_EXTI_ClearPending+0x18>)
 8002346:	6019      	str	r1, [r3, #0]
 8002348:	bd10      	pop	{r4, pc}
 800234a:	0000      	.short	0x0000
 800234c:	40010414 	.word	0x40010414

08002350 <HAL_EXTI_GenerateSWI>:
 8002350:	7802      	ldrb	r2, [r0, #0]
 8002352:	f002 031f 	and.w	r3, r2, #31
 8002356:	2201      	movs	r2, #1
 8002358:	fa02 f103 	lsl.w	r1, r2, r3
 800235c:	4a01      	ldr	r2, [pc, #4]	@ (8002364 <HAL_EXTI_GenerateSWI+0x14>)
 800235e:	6011      	str	r1, [r2, #0]
 8002360:	4770      	bx	lr
 8002362:	0000      	.short	0x0000
 8002364:	40010410 	.word	0x40010410

08002368 <HAL_EXTI_GetConfigLine>:
 8002368:	b570      	push	{r4, r5, r6, lr}
 800236a:	4604      	mov	r4, r0
 800236c:	b104      	cbz	r4, 8002370 <HAL_EXTI_GetConfigLine+0x8>
 800236e:	b909      	cbnz	r1, 8002374 <HAL_EXTI_GetConfigLine+0xc>
 8002370:	2001      	movs	r0, #1
 8002372:	bd70      	pop	{r4, r5, r6, pc}
 8002374:	6820      	ldr	r0, [r4, #0]
 8002376:	6008      	str	r0, [r1, #0]
 8002378:	7808      	ldrb	r0, [r1, #0]
 800237a:	f000 031f 	and.w	r3, r0, #31
 800237e:	2001      	movs	r0, #1
 8002380:	fa00 f203 	lsl.w	r2, r0, r3
 8002384:	481d      	ldr	r0, [pc, #116]	@ (80023fc <HAL_EXTI_GetConfigLine+0x94>)
 8002386:	6800      	ldr	r0, [r0, #0]
 8002388:	4010      	ands	r0, r2
 800238a:	b110      	cbz	r0, 8002392 <HAL_EXTI_GetConfigLine+0x2a>
 800238c:	2001      	movs	r0, #1
 800238e:	6048      	str	r0, [r1, #4]
 8002390:	e001      	b.n	8002396 <HAL_EXTI_GetConfigLine+0x2e>
 8002392:	2000      	movs	r0, #0
 8002394:	6048      	str	r0, [r1, #4]
 8002396:	4819      	ldr	r0, [pc, #100]	@ (80023fc <HAL_EXTI_GetConfigLine+0x94>)
 8002398:	1d00      	adds	r0, r0, #4
 800239a:	6800      	ldr	r0, [r0, #0]
 800239c:	4010      	ands	r0, r2
 800239e:	b118      	cbz	r0, 80023a8 <HAL_EXTI_GetConfigLine+0x40>
 80023a0:	6848      	ldr	r0, [r1, #4]
 80023a2:	f040 0002 	orr.w	r0, r0, #2
 80023a6:	6048      	str	r0, [r1, #4]
 80023a8:	2000      	movs	r0, #0
 80023aa:	6088      	str	r0, [r1, #8]
 80023ac:	60c8      	str	r0, [r1, #12]
 80023ae:	6808      	ldr	r0, [r1, #0]
 80023b0:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 80023b4:	b300      	cbz	r0, 80023f8 <HAL_EXTI_GetConfigLine+0x90>
 80023b6:	4811      	ldr	r0, [pc, #68]	@ (80023fc <HAL_EXTI_GetConfigLine+0x94>)
 80023b8:	3008      	adds	r0, #8
 80023ba:	6800      	ldr	r0, [r0, #0]
 80023bc:	4010      	ands	r0, r2
 80023be:	b108      	cbz	r0, 80023c4 <HAL_EXTI_GetConfigLine+0x5c>
 80023c0:	2001      	movs	r0, #1
 80023c2:	6088      	str	r0, [r1, #8]
 80023c4:	480d      	ldr	r0, [pc, #52]	@ (80023fc <HAL_EXTI_GetConfigLine+0x94>)
 80023c6:	300c      	adds	r0, #12
 80023c8:	6800      	ldr	r0, [r0, #0]
 80023ca:	4010      	ands	r0, r2
 80023cc:	b118      	cbz	r0, 80023d6 <HAL_EXTI_GetConfigLine+0x6e>
 80023ce:	6888      	ldr	r0, [r1, #8]
 80023d0:	f040 0002 	orr.w	r0, r0, #2
 80023d4:	6088      	str	r0, [r1, #8]
 80023d6:	6808      	ldr	r0, [r1, #0]
 80023d8:	f000 60c0 	and.w	r0, r0, #100663296	@ 0x6000000
 80023dc:	f1b0 6fc0 	cmp.w	r0, #100663296	@ 0x6000000
 80023e0:	d10a      	bne.n	80023f8 <HAL_EXTI_GetConfigLine+0x90>
 80023e2:	4807      	ldr	r0, [pc, #28]	@ (8002400 <HAL_EXTI_GetConfigLine+0x98>)
 80023e4:	089e      	lsrs	r6, r3, #2
 80023e6:	f850 5026 	ldr.w	r5, [r0, r6, lsl #2]
 80023ea:	0798      	lsls	r0, r3, #30
 80023ec:	0f00      	lsrs	r0, r0, #28
 80023ee:	fa25 f000 	lsr.w	r0, r5, r0
 80023f2:	f000 000f 	and.w	r0, r0, #15
 80023f6:	60c8      	str	r0, [r1, #12]
 80023f8:	2000      	movs	r0, #0
 80023fa:	e7ba      	b.n	8002372 <HAL_EXTI_GetConfigLine+0xa>
 80023fc:	40010400 	.word	0x40010400
 8002400:	40010008 	.word	0x40010008

08002404 <HAL_EXTI_GetHandle>:
 8002404:	4602      	mov	r2, r0
 8002406:	b90a      	cbnz	r2, 800240c <HAL_EXTI_GetHandle+0x8>
 8002408:	2001      	movs	r0, #1
 800240a:	4770      	bx	lr
 800240c:	6011      	str	r1, [r2, #0]
 800240e:	2000      	movs	r0, #0
 8002410:	e7fb      	b.n	800240a <HAL_EXTI_GetHandle+0x6>
	...

08002414 <HAL_EXTI_GetPending>:
 8002414:	b530      	push	{r4, r5, lr}
 8002416:	4602      	mov	r2, r0
 8002418:	460d      	mov	r5, r1
 800241a:	7814      	ldrb	r4, [r2, #0]
 800241c:	f004 011f 	and.w	r1, r4, #31
 8002420:	2401      	movs	r4, #1
 8002422:	fa04 f301 	lsl.w	r3, r4, r1
 8002426:	4c03      	ldr	r4, [pc, #12]	@ (8002434 <HAL_EXTI_GetPending+0x20>)
 8002428:	6824      	ldr	r4, [r4, #0]
 800242a:	401c      	ands	r4, r3
 800242c:	fa24 f001 	lsr.w	r0, r4, r1
 8002430:	bd30      	pop	{r4, r5, pc}
 8002432:	0000      	.short	0x0000
 8002434:	40010414 	.word	0x40010414

08002438 <HAL_EXTI_IRQHandler>:
 8002438:	b570      	push	{r4, r5, r6, lr}
 800243a:	4604      	mov	r4, r0
 800243c:	7820      	ldrb	r0, [r4, #0]
 800243e:	f000 011f 	and.w	r1, r0, #31
 8002442:	2001      	movs	r0, #1
 8002444:	fa00 f501 	lsl.w	r5, r0, r1
 8002448:	4805      	ldr	r0, [pc, #20]	@ (8002460 <HAL_EXTI_IRQHandler+0x28>)
 800244a:	6800      	ldr	r0, [r0, #0]
 800244c:	ea00 0605 	and.w	r6, r0, r5
 8002450:	b12e      	cbz	r6, 800245e <HAL_EXTI_IRQHandler+0x26>
 8002452:	4803      	ldr	r0, [pc, #12]	@ (8002460 <HAL_EXTI_IRQHandler+0x28>)
 8002454:	6005      	str	r5, [r0, #0]
 8002456:	6860      	ldr	r0, [r4, #4]
 8002458:	b108      	cbz	r0, 800245e <HAL_EXTI_IRQHandler+0x26>
 800245a:	6860      	ldr	r0, [r4, #4]
 800245c:	4780      	blx	r0
 800245e:	bd70      	pop	{r4, r5, r6, pc}
 8002460:	40010414 	.word	0x40010414

08002464 <HAL_EXTI_RegisterCallback>:
 8002464:	b510      	push	{r4, lr}
 8002466:	4603      	mov	r3, r0
 8002468:	2000      	movs	r0, #0
 800246a:	b909      	cbnz	r1, 8002470 <HAL_EXTI_RegisterCallback+0xc>
 800246c:	605a      	str	r2, [r3, #4]
 800246e:	e001      	b.n	8002474 <HAL_EXTI_RegisterCallback+0x10>
 8002470:	2001      	movs	r0, #1
 8002472:	bf00      	nop
 8002474:	bf00      	nop
 8002476:	bd10      	pop	{r4, pc}

08002478 <HAL_EXTI_SetConfigLine>:
 8002478:	b570      	push	{r4, r5, r6, lr}
 800247a:	4604      	mov	r4, r0
 800247c:	b104      	cbz	r4, 8002480 <HAL_EXTI_SetConfigLine+0x8>
 800247e:	b909      	cbnz	r1, 8002484 <HAL_EXTI_SetConfigLine+0xc>
 8002480:	2001      	movs	r0, #1
 8002482:	bd70      	pop	{r4, r5, r6, pc}
 8002484:	6808      	ldr	r0, [r1, #0]
 8002486:	6020      	str	r0, [r4, #0]
 8002488:	7808      	ldrb	r0, [r1, #0]
 800248a:	f000 031f 	and.w	r3, r0, #31
 800248e:	2001      	movs	r0, #1
 8002490:	fa00 f203 	lsl.w	r2, r0, r3
 8002494:	6808      	ldr	r0, [r1, #0]
 8002496:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 800249a:	b3c8      	cbz	r0, 8002510 <HAL_EXTI_SetConfigLine+0x98>
 800249c:	7a08      	ldrb	r0, [r1, #8]
 800249e:	f000 0001 	and.w	r0, r0, #1
 80024a2:	b128      	cbz	r0, 80024b0 <HAL_EXTI_SetConfigLine+0x38>
 80024a4:	482e      	ldr	r0, [pc, #184]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024a6:	6800      	ldr	r0, [r0, #0]
 80024a8:	4310      	orrs	r0, r2
 80024aa:	4e2d      	ldr	r6, [pc, #180]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024ac:	6030      	str	r0, [r6, #0]
 80024ae:	e004      	b.n	80024ba <HAL_EXTI_SetConfigLine+0x42>
 80024b0:	482b      	ldr	r0, [pc, #172]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024b2:	6800      	ldr	r0, [r0, #0]
 80024b4:	4390      	bics	r0, r2
 80024b6:	4e2a      	ldr	r6, [pc, #168]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024b8:	6030      	str	r0, [r6, #0]
 80024ba:	7a08      	ldrb	r0, [r1, #8]
 80024bc:	f000 0002 	and.w	r0, r0, #2
 80024c0:	b138      	cbz	r0, 80024d2 <HAL_EXTI_SetConfigLine+0x5a>
 80024c2:	4827      	ldr	r0, [pc, #156]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024c4:	1d00      	adds	r0, r0, #4
 80024c6:	6800      	ldr	r0, [r0, #0]
 80024c8:	4310      	orrs	r0, r2
 80024ca:	4e25      	ldr	r6, [pc, #148]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024cc:	1d36      	adds	r6, r6, #4
 80024ce:	6030      	str	r0, [r6, #0]
 80024d0:	e006      	b.n	80024e0 <HAL_EXTI_SetConfigLine+0x68>
 80024d2:	4823      	ldr	r0, [pc, #140]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024d4:	1d00      	adds	r0, r0, #4
 80024d6:	6800      	ldr	r0, [r0, #0]
 80024d8:	4390      	bics	r0, r2
 80024da:	4e21      	ldr	r6, [pc, #132]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 80024dc:	1d36      	adds	r6, r6, #4
 80024de:	6030      	str	r0, [r6, #0]
 80024e0:	6808      	ldr	r0, [r1, #0]
 80024e2:	f000 60c0 	and.w	r0, r0, #100663296	@ 0x6000000
 80024e6:	f1b0 6fc0 	cmp.w	r0, #100663296	@ 0x6000000
 80024ea:	d111      	bne.n	8002510 <HAL_EXTI_SetConfigLine+0x98>
 80024ec:	481d      	ldr	r0, [pc, #116]	@ (8002564 <HAL_EXTI_SetConfigLine+0xec>)
 80024ee:	089e      	lsrs	r6, r3, #2
 80024f0:	f850 5026 	ldr.w	r5, [r0, r6, lsl #2]
 80024f4:	0798      	lsls	r0, r3, #30
 80024f6:	0f06      	lsrs	r6, r0, #28
 80024f8:	200f      	movs	r0, #15
 80024fa:	40b0      	lsls	r0, r6
 80024fc:	4385      	bics	r5, r0
 80024fe:	079e      	lsls	r6, r3, #30
 8002500:	0f36      	lsrs	r6, r6, #28
 8002502:	68c8      	ldr	r0, [r1, #12]
 8002504:	40b0      	lsls	r0, r6
 8002506:	4305      	orrs	r5, r0
 8002508:	4816      	ldr	r0, [pc, #88]	@ (8002564 <HAL_EXTI_SetConfigLine+0xec>)
 800250a:	089e      	lsrs	r6, r3, #2
 800250c:	f840 5026 	str.w	r5, [r0, r6, lsl #2]
 8002510:	7908      	ldrb	r0, [r1, #4]
 8002512:	f000 0001 	and.w	r0, r0, #1
 8002516:	b138      	cbz	r0, 8002528 <HAL_EXTI_SetConfigLine+0xb0>
 8002518:	4811      	ldr	r0, [pc, #68]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 800251a:	3808      	subs	r0, #8
 800251c:	6800      	ldr	r0, [r0, #0]
 800251e:	4310      	orrs	r0, r2
 8002520:	4e0f      	ldr	r6, [pc, #60]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 8002522:	3e08      	subs	r6, #8
 8002524:	6030      	str	r0, [r6, #0]
 8002526:	e006      	b.n	8002536 <HAL_EXTI_SetConfigLine+0xbe>
 8002528:	480d      	ldr	r0, [pc, #52]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 800252a:	3808      	subs	r0, #8
 800252c:	6800      	ldr	r0, [r0, #0]
 800252e:	4390      	bics	r0, r2
 8002530:	4e0b      	ldr	r6, [pc, #44]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 8002532:	3e08      	subs	r6, #8
 8002534:	6030      	str	r0, [r6, #0]
 8002536:	7908      	ldrb	r0, [r1, #4]
 8002538:	f000 0002 	and.w	r0, r0, #2
 800253c:	b138      	cbz	r0, 800254e <HAL_EXTI_SetConfigLine+0xd6>
 800253e:	4808      	ldr	r0, [pc, #32]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 8002540:	1f00      	subs	r0, r0, #4
 8002542:	6800      	ldr	r0, [r0, #0]
 8002544:	4310      	orrs	r0, r2
 8002546:	4e06      	ldr	r6, [pc, #24]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 8002548:	1f36      	subs	r6, r6, #4
 800254a:	6030      	str	r0, [r6, #0]
 800254c:	e006      	b.n	800255c <HAL_EXTI_SetConfigLine+0xe4>
 800254e:	4804      	ldr	r0, [pc, #16]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 8002550:	1f00      	subs	r0, r0, #4
 8002552:	6800      	ldr	r0, [r0, #0]
 8002554:	4390      	bics	r0, r2
 8002556:	4e02      	ldr	r6, [pc, #8]	@ (8002560 <HAL_EXTI_SetConfigLine+0xe8>)
 8002558:	1f36      	subs	r6, r6, #4
 800255a:	6030      	str	r0, [r6, #0]
 800255c:	2000      	movs	r0, #0
 800255e:	e790      	b.n	8002482 <HAL_EXTI_SetConfigLine+0xa>
 8002560:	40010408 	.word	0x40010408
 8002564:	40010008 	.word	0x40010008

08002568 <HAL_FLASHEx_Erase>:
 8002568:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 800256c:	4604      	mov	r4, r0
 800256e:	460e      	mov	r6, r1
 8002570:	2701      	movs	r7, #1
 8002572:	2500      	movs	r5, #0
 8002574:	bf00      	nop
 8002576:	4826      	ldr	r0, [pc, #152]	@ (8002610 <HAL_FLASHEx_Erase+0xa8>)
 8002578:	7e00      	ldrb	r0, [r0, #24]
 800257a:	2801      	cmp	r0, #1
 800257c:	d102      	bne.n	8002584 <HAL_FLASHEx_Erase+0x1c>
 800257e:	2002      	movs	r0, #2
 8002580:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
 8002584:	2001      	movs	r0, #1
 8002586:	4922      	ldr	r1, [pc, #136]	@ (8002610 <HAL_FLASHEx_Erase+0xa8>)
 8002588:	7608      	strb	r0, [r1, #24]
 800258a:	bf00      	nop
 800258c:	6820      	ldr	r0, [r4, #0]
 800258e:	2802      	cmp	r0, #2
 8002590:	d113      	bne.n	80025ba <HAL_FLASHEx_Erase+0x52>
 8002592:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8002596:	f7fe fe83 	bl	80012a0 <FLASH_WaitForLastOperation>
 800259a:	bb90      	cbnz	r0, 8002602 <HAL_FLASHEx_Erase+0x9a>
 800259c:	2001      	movs	r0, #1
 800259e:	f7fe fc71 	bl	8000e84 <FLASH_MassErase>
 80025a2:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80025a6:	f7fe fe7b 	bl	80012a0 <FLASH_WaitForLastOperation>
 80025aa:	4607      	mov	r7, r0
 80025ac:	4819      	ldr	r0, [pc, #100]	@ (8002614 <HAL_FLASHEx_Erase+0xac>)
 80025ae:	6900      	ldr	r0, [r0, #16]
 80025b0:	f020 0004 	bic.w	r0, r0, #4
 80025b4:	4917      	ldr	r1, [pc, #92]	@ (8002614 <HAL_FLASHEx_Erase+0xac>)
 80025b6:	6108      	str	r0, [r1, #16]
 80025b8:	e023      	b.n	8002602 <HAL_FLASHEx_Erase+0x9a>
 80025ba:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80025be:	f7fe fe6f 	bl	80012a0 <FLASH_WaitForLastOperation>
 80025c2:	b9f0      	cbnz	r0, 8002602 <HAL_FLASHEx_Erase+0x9a>
 80025c4:	f04f 30ff 	mov.w	r0, #4294967295
 80025c8:	6030      	str	r0, [r6, #0]
 80025ca:	68a5      	ldr	r5, [r4, #8]
 80025cc:	e012      	b.n	80025f4 <HAL_FLASHEx_Erase+0x8c>
 80025ce:	4628      	mov	r0, r5
 80025d0:	f7fe fe00 	bl	80011d4 <FLASH_PageErase>
 80025d4:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80025d8:	f7fe fe62 	bl	80012a0 <FLASH_WaitForLastOperation>
 80025dc:	4607      	mov	r7, r0
 80025de:	480d      	ldr	r0, [pc, #52]	@ (8002614 <HAL_FLASHEx_Erase+0xac>)
 80025e0:	6900      	ldr	r0, [r0, #16]
 80025e2:	f020 0002 	bic.w	r0, r0, #2
 80025e6:	490b      	ldr	r1, [pc, #44]	@ (8002614 <HAL_FLASHEx_Erase+0xac>)
 80025e8:	6108      	str	r0, [r1, #16]
 80025ea:	b10f      	cbz	r7, 80025f0 <HAL_FLASHEx_Erase+0x88>
 80025ec:	6035      	str	r5, [r6, #0]
 80025ee:	e007      	b.n	8002600 <HAL_FLASHEx_Erase+0x98>
 80025f0:	f505 6500 	add.w	r5, r5, #2048	@ 0x800
 80025f4:	e9d4 1002 	ldrd	r1, r0, [r4, #8]
 80025f8:	eb01 20c0 	add.w	r0, r1, r0, lsl #11
 80025fc:	42a8      	cmp	r0, r5
 80025fe:	d8e6      	bhi.n	80025ce <HAL_FLASHEx_Erase+0x66>
 8002600:	bf00      	nop
 8002602:	bf00      	nop
 8002604:	2000      	movs	r0, #0
 8002606:	4902      	ldr	r1, [pc, #8]	@ (8002610 <HAL_FLASHEx_Erase+0xa8>)
 8002608:	7608      	strb	r0, [r1, #24]
 800260a:	bf00      	nop
 800260c:	4638      	mov	r0, r7
 800260e:	e7b7      	b.n	8002580 <HAL_FLASHEx_Erase+0x18>
 8002610:	20000070 	.word	0x20000070
 8002614:	40022000 	.word	0x40022000

08002618 <HAL_FLASHEx_Erase_IT>:
 8002618:	b570      	push	{r4, r5, r6, lr}
 800261a:	4604      	mov	r4, r0
 800261c:	2500      	movs	r5, #0
 800261e:	4810      	ldr	r0, [pc, #64]	@ (8002660 <HAL_FLASHEx_Erase_IT+0x48>)
 8002620:	7800      	ldrb	r0, [r0, #0]
 8002622:	b108      	cbz	r0, 8002628 <HAL_FLASHEx_Erase_IT+0x10>
 8002624:	2001      	movs	r0, #1
 8002626:	bd70      	pop	{r4, r5, r6, pc}
 8002628:	480e      	ldr	r0, [pc, #56]	@ (8002664 <HAL_FLASHEx_Erase_IT+0x4c>)
 800262a:	6900      	ldr	r0, [r0, #16]
 800262c:	f440 50a0 	orr.w	r0, r0, #5120	@ 0x1400
 8002630:	490c      	ldr	r1, [pc, #48]	@ (8002664 <HAL_FLASHEx_Erase_IT+0x4c>)
 8002632:	6108      	str	r0, [r1, #16]
 8002634:	6820      	ldr	r0, [r4, #0]
 8002636:	2802      	cmp	r0, #2
 8002638:	d105      	bne.n	8002646 <HAL_FLASHEx_Erase_IT+0x2e>
 800263a:	4909      	ldr	r1, [pc, #36]	@ (8002660 <HAL_FLASHEx_Erase_IT+0x48>)
 800263c:	7008      	strb	r0, [r1, #0]
 800263e:	6860      	ldr	r0, [r4, #4]
 8002640:	f7fe fc20 	bl	8000e84 <FLASH_MassErase>
 8002644:	e009      	b.n	800265a <HAL_FLASHEx_Erase_IT+0x42>
 8002646:	2001      	movs	r0, #1
 8002648:	4905      	ldr	r1, [pc, #20]	@ (8002660 <HAL_FLASHEx_Erase_IT+0x48>)
 800264a:	7008      	strb	r0, [r1, #0]
 800264c:	68e0      	ldr	r0, [r4, #12]
 800264e:	6048      	str	r0, [r1, #4]
 8002650:	68a0      	ldr	r0, [r4, #8]
 8002652:	6088      	str	r0, [r1, #8]
 8002654:	68a0      	ldr	r0, [r4, #8]
 8002656:	f7fe fdbd 	bl	80011d4 <FLASH_PageErase>
 800265a:	4628      	mov	r0, r5
 800265c:	e7e3      	b.n	8002626 <HAL_FLASHEx_Erase_IT+0xe>
 800265e:	0000      	.short	0x0000
 8002660:	20000070 	.word	0x20000070
 8002664:	40022000 	.word	0x40022000

08002668 <HAL_FLASHEx_OBErase>:
 8002668:	b570      	push	{r4, r5, r6, lr}
 800266a:	25a5      	movs	r5, #165	@ 0xa5
 800266c:	2401      	movs	r4, #1
 800266e:	f7fe fd07 	bl	8001080 <FLASH_OB_GetRDP>
 8002672:	b2c5      	uxtb	r5, r0
 8002674:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8002678:	f7fe fe12 	bl	80012a0 <FLASH_WaitForLastOperation>
 800267c:	4604      	mov	r4, r0
 800267e:	b9ec      	cbnz	r4, 80026bc <HAL_FLASHEx_OBErase+0x54>
 8002680:	2000      	movs	r0, #0
 8002682:	490f      	ldr	r1, [pc, #60]	@ (80026c0 <HAL_FLASHEx_OBErase+0x58>)
 8002684:	61c8      	str	r0, [r1, #28]
 8002686:	480f      	ldr	r0, [pc, #60]	@ (80026c4 <HAL_FLASHEx_OBErase+0x5c>)
 8002688:	6900      	ldr	r0, [r0, #16]
 800268a:	f040 0020 	orr.w	r0, r0, #32
 800268e:	490d      	ldr	r1, [pc, #52]	@ (80026c4 <HAL_FLASHEx_OBErase+0x5c>)
 8002690:	6108      	str	r0, [r1, #16]
 8002692:	4608      	mov	r0, r1
 8002694:	6900      	ldr	r0, [r0, #16]
 8002696:	f040 0040 	orr.w	r0, r0, #64	@ 0x40
 800269a:	6108      	str	r0, [r1, #16]
 800269c:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80026a0:	f7fe fdfe 	bl	80012a0 <FLASH_WaitForLastOperation>
 80026a4:	4604      	mov	r4, r0
 80026a6:	4807      	ldr	r0, [pc, #28]	@ (80026c4 <HAL_FLASHEx_OBErase+0x5c>)
 80026a8:	6900      	ldr	r0, [r0, #16]
 80026aa:	f020 0020 	bic.w	r0, r0, #32
 80026ae:	4905      	ldr	r1, [pc, #20]	@ (80026c4 <HAL_FLASHEx_OBErase+0x5c>)
 80026b0:	6108      	str	r0, [r1, #16]
 80026b2:	b91c      	cbnz	r4, 80026bc <HAL_FLASHEx_OBErase+0x54>
 80026b4:	4628      	mov	r0, r5
 80026b6:	f7fe fd25 	bl	8001104 <FLASH_OB_RDP_LevelConfig>
 80026ba:	4604      	mov	r4, r0
 80026bc:	4620      	mov	r0, r4
 80026be:	bd70      	pop	{r4, r5, r6, pc}
 80026c0:	20000070 	.word	0x20000070
 80026c4:	40022000 	.word	0x40022000

080026c8 <HAL_FLASHEx_OBGetConfig>:
 80026c8:	b510      	push	{r4, lr}
 80026ca:	4604      	mov	r4, r0
 80026cc:	2007      	movs	r0, #7
 80026ce:	6020      	str	r0, [r4, #0]
 80026d0:	f7fe fcec 	bl	80010ac <FLASH_OB_GetWRP>
 80026d4:	60a0      	str	r0, [r4, #8]
 80026d6:	f7fe fcd3 	bl	8001080 <FLASH_OB_GetRDP>
 80026da:	7420      	strb	r0, [r4, #16]
 80026dc:	f7fe fcde 	bl	800109c <FLASH_OB_GetUser>
 80026e0:	7460      	strb	r0, [r4, #17]
 80026e2:	bd10      	pop	{r4, pc}

080026e4 <HAL_FLASHEx_OBGetUserData>:
 80026e4:	4601      	mov	r1, r0
 80026e6:	2000      	movs	r0, #0
 80026e8:	4a06      	ldr	r2, [pc, #24]	@ (8002704 <HAL_FLASHEx_OBGetUserData+0x20>)
 80026ea:	4291      	cmp	r1, r2
 80026ec:	d104      	bne.n	80026f8 <HAL_FLASHEx_OBGetUserData+0x14>
 80026ee:	4a06      	ldr	r2, [pc, #24]	@ (8002708 <HAL_FLASHEx_OBGetUserData+0x24>)
 80026f0:	69d2      	ldr	r2, [r2, #28]
 80026f2:	f3c2 2087 	ubfx	r0, r2, #10, #8
 80026f6:	e003      	b.n	8002700 <HAL_FLASHEx_OBGetUserData+0x1c>
 80026f8:	4a03      	ldr	r2, [pc, #12]	@ (8002708 <HAL_FLASHEx_OBGetUserData+0x24>)
 80026fa:	69d2      	ldr	r2, [r2, #28]
 80026fc:	f3c2 4087 	ubfx	r0, r2, #18, #8
 8002700:	4770      	bx	lr
 8002702:	0000      	.short	0x0000
 8002704:	1ffff804 	.word	0x1ffff804
 8002708:	40022000 	.word	0x40022000

0800270c <HAL_FLASHEx_OBProgram>:
 800270c:	b570      	push	{r4, r5, r6, lr}
 800270e:	4604      	mov	r4, r0
 8002710:	2501      	movs	r5, #1
 8002712:	bf00      	nop
 8002714:	482e      	ldr	r0, [pc, #184]	@ (80027d0 <HAL_FLASHEx_OBProgram+0xc4>)
 8002716:	7e00      	ldrb	r0, [r0, #24]
 8002718:	2801      	cmp	r0, #1
 800271a:	d101      	bne.n	8002720 <HAL_FLASHEx_OBProgram+0x14>
 800271c:	2002      	movs	r0, #2
 800271e:	bd70      	pop	{r4, r5, r6, pc}
 8002720:	2001      	movs	r0, #1
 8002722:	492b      	ldr	r1, [pc, #172]	@ (80027d0 <HAL_FLASHEx_OBProgram+0xc4>)
 8002724:	7608      	strb	r0, [r1, #24]
 8002726:	bf00      	nop
 8002728:	7820      	ldrb	r0, [r4, #0]
 800272a:	f000 0001 	and.w	r0, r0, #1
 800272e:	b198      	cbz	r0, 8002758 <HAL_FLASHEx_OBProgram+0x4c>
 8002730:	6860      	ldr	r0, [r4, #4]
 8002732:	2801      	cmp	r0, #1
 8002734:	d104      	bne.n	8002740 <HAL_FLASHEx_OBProgram+0x34>
 8002736:	68a0      	ldr	r0, [r4, #8]
 8002738:	f7fe fc2c 	bl	8000f94 <FLASH_OB_EnableWRP>
 800273c:	4605      	mov	r5, r0
 800273e:	e003      	b.n	8002748 <HAL_FLASHEx_OBProgram+0x3c>
 8002740:	68a0      	ldr	r0, [r4, #8]
 8002742:	f7fe fbb3 	bl	8000eac <FLASH_OB_DisableWRP>
 8002746:	4605      	mov	r5, r0
 8002748:	b135      	cbz	r5, 8002758 <HAL_FLASHEx_OBProgram+0x4c>
 800274a:	bf00      	nop
 800274c:	2000      	movs	r0, #0
 800274e:	4920      	ldr	r1, [pc, #128]	@ (80027d0 <HAL_FLASHEx_OBProgram+0xc4>)
 8002750:	7608      	strb	r0, [r1, #24]
 8002752:	bf00      	nop
 8002754:	4628      	mov	r0, r5
 8002756:	e7e2      	b.n	800271e <HAL_FLASHEx_OBProgram+0x12>
 8002758:	7820      	ldrb	r0, [r4, #0]
 800275a:	f000 0002 	and.w	r0, r0, #2
 800275e:	2802      	cmp	r0, #2
 8002760:	d10b      	bne.n	800277a <HAL_FLASHEx_OBProgram+0x6e>
 8002762:	7c20      	ldrb	r0, [r4, #16]
 8002764:	f7fe fcce 	bl	8001104 <FLASH_OB_RDP_LevelConfig>
 8002768:	4605      	mov	r5, r0
 800276a:	b135      	cbz	r5, 800277a <HAL_FLASHEx_OBProgram+0x6e>
 800276c:	bf00      	nop
 800276e:	2000      	movs	r0, #0
 8002770:	4917      	ldr	r1, [pc, #92]	@ (80027d0 <HAL_FLASHEx_OBProgram+0xc4>)
 8002772:	7608      	strb	r0, [r1, #24]
 8002774:	bf00      	nop
 8002776:	4628      	mov	r0, r5
 8002778:	e7d1      	b.n	800271e <HAL_FLASHEx_OBProgram+0x12>
 800277a:	7820      	ldrb	r0, [r4, #0]
 800277c:	f000 0004 	and.w	r0, r0, #4
 8002780:	2804      	cmp	r0, #4
 8002782:	d10b      	bne.n	800279c <HAL_FLASHEx_OBProgram+0x90>
 8002784:	7c60      	ldrb	r0, [r4, #17]
 8002786:	f7fe fcfb 	bl	8001180 <FLASH_OB_UserConfig>
 800278a:	4605      	mov	r5, r0
 800278c:	b135      	cbz	r5, 800279c <HAL_FLASHEx_OBProgram+0x90>
 800278e:	bf00      	nop
 8002790:	2000      	movs	r0, #0
 8002792:	490f      	ldr	r1, [pc, #60]	@ (80027d0 <HAL_FLASHEx_OBProgram+0xc4>)
 8002794:	7608      	strb	r0, [r1, #24]
 8002796:	bf00      	nop
 8002798:	4628      	mov	r0, r5
 800279a:	e7c0      	b.n	800271e <HAL_FLASHEx_OBProgram+0x12>
 800279c:	7820      	ldrb	r0, [r4, #0]
 800279e:	f000 0008 	and.w	r0, r0, #8
 80027a2:	2808      	cmp	r0, #8
 80027a4:	d10c      	bne.n	80027c0 <HAL_FLASHEx_OBProgram+0xb4>
 80027a6:	7e21      	ldrb	r1, [r4, #24]
 80027a8:	6960      	ldr	r0, [r4, #20]
 80027aa:	f7fe fc85 	bl	80010b8 <FLASH_OB_ProgramData>
 80027ae:	4605      	mov	r5, r0
 80027b0:	b135      	cbz	r5, 80027c0 <HAL_FLASHEx_OBProgram+0xb4>
 80027b2:	bf00      	nop
 80027b4:	2000      	movs	r0, #0
 80027b6:	4906      	ldr	r1, [pc, #24]	@ (80027d0 <HAL_FLASHEx_OBProgram+0xc4>)
 80027b8:	7608      	strb	r0, [r1, #24]
 80027ba:	bf00      	nop
 80027bc:	4628      	mov	r0, r5
 80027be:	e7ae      	b.n	800271e <HAL_FLASHEx_OBProgram+0x12>
 80027c0:	bf00      	nop
 80027c2:	2000      	movs	r0, #0
 80027c4:	4902      	ldr	r1, [pc, #8]	@ (80027d0 <HAL_FLASHEx_OBProgram+0xc4>)
 80027c6:	7608      	strb	r0, [r1, #24]
 80027c8:	bf00      	nop
 80027ca:	4628      	mov	r0, r5
 80027cc:	e7a7      	b.n	800271e <HAL_FLASHEx_OBProgram+0x12>
 80027ce:	0000      	.short	0x0000
 80027d0:	20000070 	.word	0x20000070

080027d4 <HAL_FLASH_EndOfOperationCallback>:
 80027d4:	4770      	bx	lr
	...

080027d8 <HAL_FLASH_GetError>:
 80027d8:	4801      	ldr	r0, [pc, #4]	@ (80027e0 <HAL_FLASH_GetError+0x8>)
 80027da:	69c0      	ldr	r0, [r0, #28]
 80027dc:	4770      	bx	lr
 80027de:	0000      	.short	0x0000
 80027e0:	20000070 	.word	0x20000070

080027e4 <HAL_FLASH_IRQHandler>:
 80027e4:	b510      	push	{r4, lr}
 80027e6:	2400      	movs	r4, #0
 80027e8:	485a      	ldr	r0, [pc, #360]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 80027ea:	68c0      	ldr	r0, [r0, #12]
 80027ec:	f000 0010 	and.w	r0, r0, #16
 80027f0:	b920      	cbnz	r0, 80027fc <HAL_FLASH_IRQHandler+0x18>
 80027f2:	4858      	ldr	r0, [pc, #352]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 80027f4:	68c0      	ldr	r0, [r0, #12]
 80027f6:	f000 0004 	and.w	r0, r0, #4
 80027fa:	b168      	cbz	r0, 8002818 <HAL_FLASH_IRQHandler+0x34>
 80027fc:	4856      	ldr	r0, [pc, #344]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 80027fe:	6884      	ldr	r4, [r0, #8]
 8002800:	f04f 30ff 	mov.w	r0, #4294967295
 8002804:	4954      	ldr	r1, [pc, #336]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002806:	6088      	str	r0, [r1, #8]
 8002808:	f7fe fd08 	bl	800121c <FLASH_SetErrorCode>
 800280c:	4620      	mov	r0, r4
 800280e:	f000 f8d3 	bl	80029b8 <HAL_FLASH_OperationErrorCallback>
 8002812:	2000      	movs	r0, #0
 8002814:	4950      	ldr	r1, [pc, #320]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002816:	7008      	strb	r0, [r1, #0]
 8002818:	484e      	ldr	r0, [pc, #312]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 800281a:	68c0      	ldr	r0, [r0, #12]
 800281c:	f000 0020 	and.w	r0, r0, #32
 8002820:	2800      	cmp	r0, #0
 8002822:	d028      	beq.n	8002876 <HAL_FLASH_IRQHandler+0x92>
 8002824:	bf00      	nop
 8002826:	2020      	movs	r0, #32
 8002828:	494a      	ldr	r1, [pc, #296]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 800282a:	60c8      	str	r0, [r1, #12]
 800282c:	bf00      	nop
 800282e:	484a      	ldr	r0, [pc, #296]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002830:	7800      	ldrb	r0, [r0, #0]
 8002832:	2800      	cmp	r0, #0
 8002834:	d07e      	beq.n	8002934 <HAL_FLASH_IRQHandler+0x150>
 8002836:	4848      	ldr	r0, [pc, #288]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002838:	7800      	ldrb	r0, [r0, #0]
 800283a:	2801      	cmp	r0, #1
 800283c:	d127      	bne.n	800288e <HAL_FLASH_IRQHandler+0xaa>
 800283e:	4846      	ldr	r0, [pc, #280]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002840:	6840      	ldr	r0, [r0, #4]
 8002842:	1e40      	subs	r0, r0, #1
 8002844:	4944      	ldr	r1, [pc, #272]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002846:	6048      	str	r0, [r1, #4]
 8002848:	4608      	mov	r0, r1
 800284a:	6840      	ldr	r0, [r0, #4]
 800284c:	b1a0      	cbz	r0, 8002878 <HAL_FLASH_IRQHandler+0x94>
 800284e:	4608      	mov	r0, r1
 8002850:	6884      	ldr	r4, [r0, #8]
 8002852:	4620      	mov	r0, r4
 8002854:	f7ff ffbe 	bl	80027d4 <HAL_FLASH_EndOfOperationCallback>
 8002858:	483f      	ldr	r0, [pc, #252]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 800285a:	6880      	ldr	r0, [r0, #8]
 800285c:	f500 6400 	add.w	r4, r0, #2048	@ 0x800
 8002860:	483d      	ldr	r0, [pc, #244]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002862:	6084      	str	r4, [r0, #8]
 8002864:	483b      	ldr	r0, [pc, #236]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 8002866:	6900      	ldr	r0, [r0, #16]
 8002868:	f020 0002 	bic.w	r0, r0, #2
 800286c:	4939      	ldr	r1, [pc, #228]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 800286e:	6108      	str	r0, [r1, #16]
 8002870:	4620      	mov	r0, r4
 8002872:	f7fe fcaf 	bl	80011d4 <FLASH_PageErase>
 8002876:	e05d      	b.n	8002934 <HAL_FLASH_IRQHandler+0x150>
 8002878:	f04f 30ff 	mov.w	r0, #4294967295
 800287c:	4604      	mov	r4, r0
 800287e:	4936      	ldr	r1, [pc, #216]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002880:	6088      	str	r0, [r1, #8]
 8002882:	2000      	movs	r0, #0
 8002884:	7008      	strb	r0, [r1, #0]
 8002886:	4620      	mov	r0, r4
 8002888:	f7ff ffa4 	bl	80027d4 <HAL_FLASH_EndOfOperationCallback>
 800288c:	e052      	b.n	8002934 <HAL_FLASH_IRQHandler+0x150>
 800288e:	4832      	ldr	r0, [pc, #200]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002890:	7800      	ldrb	r0, [r0, #0]
 8002892:	2802      	cmp	r0, #2
 8002894:	d10c      	bne.n	80028b0 <HAL_FLASH_IRQHandler+0xcc>
 8002896:	482f      	ldr	r0, [pc, #188]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 8002898:	6900      	ldr	r0, [r0, #16]
 800289a:	f020 0004 	bic.w	r0, r0, #4
 800289e:	492d      	ldr	r1, [pc, #180]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 80028a0:	6108      	str	r0, [r1, #16]
 80028a2:	2000      	movs	r0, #0
 80028a4:	f7ff ff96 	bl	80027d4 <HAL_FLASH_EndOfOperationCallback>
 80028a8:	2000      	movs	r0, #0
 80028aa:	492b      	ldr	r1, [pc, #172]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 80028ac:	7008      	strb	r0, [r1, #0]
 80028ae:	e041      	b.n	8002934 <HAL_FLASH_IRQHandler+0x150>
 80028b0:	4829      	ldr	r0, [pc, #164]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 80028b2:	6840      	ldr	r0, [r0, #4]
 80028b4:	1e40      	subs	r0, r0, #1
 80028b6:	4928      	ldr	r1, [pc, #160]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 80028b8:	6048      	str	r0, [r1, #4]
 80028ba:	4608      	mov	r0, r1
 80028bc:	6840      	ldr	r0, [r0, #4]
 80028be:	b1d8      	cbz	r0, 80028f8 <HAL_FLASH_IRQHandler+0x114>
 80028c0:	4608      	mov	r0, r1
 80028c2:	6880      	ldr	r0, [r0, #8]
 80028c4:	1c80      	adds	r0, r0, #2
 80028c6:	6088      	str	r0, [r1, #8]
 80028c8:	4608      	mov	r0, r1
 80028ca:	6884      	ldr	r4, [r0, #8]
 80028cc:	6908      	ldr	r0, [r1, #16]
 80028ce:	6949      	ldr	r1, [r1, #20]
 80028d0:	0c00      	lsrs	r0, r0, #16
 80028d2:	ea40 4001 	orr.w	r0, r0, r1, lsl #16
 80028d6:	0c09      	lsrs	r1, r1, #16
 80028d8:	4a1f      	ldr	r2, [pc, #124]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 80028da:	6110      	str	r0, [r2, #16]
 80028dc:	6151      	str	r1, [r2, #20]
 80028de:	481d      	ldr	r0, [pc, #116]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 80028e0:	6900      	ldr	r0, [r0, #16]
 80028e2:	f020 0001 	bic.w	r0, r0, #1
 80028e6:	491b      	ldr	r1, [pc, #108]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 80028e8:	6108      	str	r0, [r1, #16]
 80028ea:	6910      	ldr	r0, [r2, #16]
 80028ec:	6952      	ldr	r2, [r2, #20]
 80028ee:	b281      	uxth	r1, r0
 80028f0:	4620      	mov	r0, r4
 80028f2:	f7fe fc83 	bl	80011fc <FLASH_Program_HalfWord>
 80028f6:	e01d      	b.n	8002934 <HAL_FLASH_IRQHandler+0x150>
 80028f8:	4817      	ldr	r0, [pc, #92]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 80028fa:	7800      	ldrb	r0, [r0, #0]
 80028fc:	2803      	cmp	r0, #3
 80028fe:	d104      	bne.n	800290a <HAL_FLASH_IRQHandler+0x126>
 8002900:	4915      	ldr	r1, [pc, #84]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002902:	6888      	ldr	r0, [r1, #8]
 8002904:	f7ff ff66 	bl	80027d4 <HAL_FLASH_EndOfOperationCallback>
 8002908:	e00e      	b.n	8002928 <HAL_FLASH_IRQHandler+0x144>
 800290a:	4813      	ldr	r0, [pc, #76]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 800290c:	7800      	ldrb	r0, [r0, #0]
 800290e:	2804      	cmp	r0, #4
 8002910:	d105      	bne.n	800291e <HAL_FLASH_IRQHandler+0x13a>
 8002912:	4911      	ldr	r1, [pc, #68]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002914:	6889      	ldr	r1, [r1, #8]
 8002916:	1e88      	subs	r0, r1, #2
 8002918:	f7ff ff5c 	bl	80027d4 <HAL_FLASH_EndOfOperationCallback>
 800291c:	e004      	b.n	8002928 <HAL_FLASH_IRQHandler+0x144>
 800291e:	490e      	ldr	r1, [pc, #56]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002920:	6889      	ldr	r1, [r1, #8]
 8002922:	1f88      	subs	r0, r1, #6
 8002924:	f7ff ff56 	bl	80027d4 <HAL_FLASH_EndOfOperationCallback>
 8002928:	f04f 30ff 	mov.w	r0, #4294967295
 800292c:	490a      	ldr	r1, [pc, #40]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 800292e:	6088      	str	r0, [r1, #8]
 8002930:	2000      	movs	r0, #0
 8002932:	7008      	strb	r0, [r1, #0]
 8002934:	4808      	ldr	r0, [pc, #32]	@ (8002958 <HAL_FLASH_IRQHandler+0x174>)
 8002936:	7800      	ldrb	r0, [r0, #0]
 8002938:	b950      	cbnz	r0, 8002950 <HAL_FLASH_IRQHandler+0x16c>
 800293a:	4806      	ldr	r0, [pc, #24]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 800293c:	6900      	ldr	r0, [r0, #16]
 800293e:	f020 0007 	bic.w	r0, r0, #7
 8002942:	4904      	ldr	r1, [pc, #16]	@ (8002954 <HAL_FLASH_IRQHandler+0x170>)
 8002944:	6108      	str	r0, [r1, #16]
 8002946:	4608      	mov	r0, r1
 8002948:	6900      	ldr	r0, [r0, #16]
 800294a:	f420 50a0 	bic.w	r0, r0, #5120	@ 0x1400
 800294e:	6108      	str	r0, [r1, #16]
 8002950:	bd10      	pop	{r4, pc}
 8002952:	0000      	.short	0x0000
 8002954:	40022000 	.word	0x40022000
 8002958:	20000070 	.word	0x20000070

0800295c <HAL_FLASH_Lock>:
 800295c:	4803      	ldr	r0, [pc, #12]	@ (800296c <HAL_FLASH_Lock+0x10>)
 800295e:	6900      	ldr	r0, [r0, #16]
 8002960:	f040 0080 	orr.w	r0, r0, #128	@ 0x80
 8002964:	4901      	ldr	r1, [pc, #4]	@ (800296c <HAL_FLASH_Lock+0x10>)
 8002966:	6108      	str	r0, [r1, #16]
 8002968:	2000      	movs	r0, #0
 800296a:	4770      	bx	lr
 800296c:	40022000 	.word	0x40022000

08002970 <HAL_FLASH_OB_Launch>:
 8002970:	b510      	push	{r4, lr}
 8002972:	f000 fed1 	bl	8003718 <HAL_NVIC_SystemReset>
 8002976:	bd10      	pop	{r4, pc}

08002978 <HAL_FLASH_OB_Lock>:
 8002978:	4803      	ldr	r0, [pc, #12]	@ (8002988 <HAL_FLASH_OB_Lock+0x10>)
 800297a:	6900      	ldr	r0, [r0, #16]
 800297c:	f420 7000 	bic.w	r0, r0, #512	@ 0x200
 8002980:	4901      	ldr	r1, [pc, #4]	@ (8002988 <HAL_FLASH_OB_Lock+0x10>)
 8002982:	6108      	str	r0, [r1, #16]
 8002984:	2000      	movs	r0, #0
 8002986:	4770      	bx	lr
 8002988:	40022000 	.word	0x40022000

0800298c <HAL_FLASH_OB_Unlock>:
 800298c:	4807      	ldr	r0, [pc, #28]	@ (80029ac <HAL_FLASH_OB_Unlock+0x20>)
 800298e:	6900      	ldr	r0, [r0, #16]
 8002990:	f400 7000 	and.w	r0, r0, #512	@ 0x200
 8002994:	b928      	cbnz	r0, 80029a2 <HAL_FLASH_OB_Unlock+0x16>
 8002996:	4806      	ldr	r0, [pc, #24]	@ (80029b0 <HAL_FLASH_OB_Unlock+0x24>)
 8002998:	4904      	ldr	r1, [pc, #16]	@ (80029ac <HAL_FLASH_OB_Unlock+0x20>)
 800299a:	6088      	str	r0, [r1, #8]
 800299c:	4805      	ldr	r0, [pc, #20]	@ (80029b4 <HAL_FLASH_OB_Unlock+0x28>)
 800299e:	6088      	str	r0, [r1, #8]
 80029a0:	e001      	b.n	80029a6 <HAL_FLASH_OB_Unlock+0x1a>
 80029a2:	2001      	movs	r0, #1
 80029a4:	4770      	bx	lr
 80029a6:	2000      	movs	r0, #0
 80029a8:	e7fc      	b.n	80029a4 <HAL_FLASH_OB_Unlock+0x18>
 80029aa:	0000      	.short	0x0000
 80029ac:	40022000 	.word	0x40022000
 80029b0:	45670123 	.word	0x45670123
 80029b4:	cdef89ab 	.word	0xcdef89ab

080029b8 <HAL_FLASH_OperationErrorCallback>:
 80029b8:	4770      	bx	lr
	...

080029bc <HAL_FLASH_Program>:
 80029bc:	e92d 4ffe 	stmdb	sp!, {r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
 80029c0:	4605      	mov	r5, r0
 80029c2:	468b      	mov	fp, r1
 80029c4:	4617      	mov	r7, r2
 80029c6:	4698      	mov	r8, r3
 80029c8:	2601      	movs	r6, #1
 80029ca:	2400      	movs	r4, #0
 80029cc:	2000      	movs	r0, #0
 80029ce:	9002      	str	r0, [sp, #8]
 80029d0:	bf00      	nop
 80029d2:	4824      	ldr	r0, [pc, #144]	@ (8002a64 <HAL_FLASH_Program+0xa8>)
 80029d4:	7e00      	ldrb	r0, [r0, #24]
 80029d6:	2801      	cmp	r0, #1
 80029d8:	d102      	bne.n	80029e0 <HAL_FLASH_Program+0x24>
 80029da:	2002      	movs	r0, #2
 80029dc:	e8bd 8ffe 	ldmia.w	sp!, {r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, pc}
 80029e0:	2001      	movs	r0, #1
 80029e2:	4920      	ldr	r1, [pc, #128]	@ (8002a64 <HAL_FLASH_Program+0xa8>)
 80029e4:	7608      	strb	r0, [r1, #24]
 80029e6:	bf00      	nop
 80029e8:	f24c 3050 	movw	r0, #50000	@ 0xc350
 80029ec:	f7fe fc58 	bl	80012a0 <FLASH_WaitForLastOperation>
 80029f0:	4606      	mov	r6, r0
 80029f2:	bb86      	cbnz	r6, 8002a56 <HAL_FLASH_Program+0x9a>
 80029f4:	2d01      	cmp	r5, #1
 80029f6:	d102      	bne.n	80029fe <HAL_FLASH_Program+0x42>
 80029f8:	2001      	movs	r0, #1
 80029fa:	9002      	str	r0, [sp, #8]
 80029fc:	e006      	b.n	8002a0c <HAL_FLASH_Program+0x50>
 80029fe:	2d02      	cmp	r5, #2
 8002a00:	d102      	bne.n	8002a08 <HAL_FLASH_Program+0x4c>
 8002a02:	2002      	movs	r0, #2
 8002a04:	9002      	str	r0, [sp, #8]
 8002a06:	e001      	b.n	8002a0c <HAL_FLASH_Program+0x50>
 8002a08:	2004      	movs	r0, #4
 8002a0a:	9002      	str	r0, [sp, #8]
 8002a0c:	2400      	movs	r4, #0
 8002a0e:	e01e      	b.n	8002a4e <HAL_FLASH_Program+0x92>
 8002a10:	0122      	lsls	r2, r4, #4
 8002a12:	46b9      	mov	r9, r7
 8002a14:	46c2      	mov	sl, r8
 8002a16:	4648      	mov	r0, r9
 8002a18:	4651      	mov	r1, sl
 8002a1a:	f7fd fc8d 	bl	8000338 <__aeabi_llsr>
 8002a1e:	b280      	uxth	r0, r0
 8002a20:	9001      	str	r0, [sp, #4]
 8002a22:	2002      	movs	r0, #2
 8002a24:	fb00 b004 	mla	r0, r0, r4, fp
 8002a28:	9000      	str	r0, [sp, #0]
 8002a2a:	9901      	ldr	r1, [sp, #4]
 8002a2c:	f7fe fbe6 	bl	80011fc <FLASH_Program_HalfWord>
 8002a30:	f24c 3050 	movw	r0, #50000	@ 0xc350
 8002a34:	f7fe fc34 	bl	80012a0 <FLASH_WaitForLastOperation>
 8002a38:	4606      	mov	r6, r0
 8002a3a:	480b      	ldr	r0, [pc, #44]	@ (8002a68 <HAL_FLASH_Program+0xac>)
 8002a3c:	6900      	ldr	r0, [r0, #16]
 8002a3e:	f020 0001 	bic.w	r0, r0, #1
 8002a42:	4909      	ldr	r1, [pc, #36]	@ (8002a68 <HAL_FLASH_Program+0xac>)
 8002a44:	6108      	str	r0, [r1, #16]
 8002a46:	b106      	cbz	r6, 8002a4a <HAL_FLASH_Program+0x8e>
 8002a48:	e004      	b.n	8002a54 <HAL_FLASH_Program+0x98>
 8002a4a:	1c60      	adds	r0, r4, #1
 8002a4c:	b2c4      	uxtb	r4, r0
 8002a4e:	9802      	ldr	r0, [sp, #8]
 8002a50:	4284      	cmp	r4, r0
 8002a52:	dbdd      	blt.n	8002a10 <HAL_FLASH_Program+0x54>
 8002a54:	bf00      	nop
 8002a56:	bf00      	nop
 8002a58:	2000      	movs	r0, #0
 8002a5a:	4902      	ldr	r1, [pc, #8]	@ (8002a64 <HAL_FLASH_Program+0xa8>)
 8002a5c:	7608      	strb	r0, [r1, #24]
 8002a5e:	bf00      	nop
 8002a60:	4630      	mov	r0, r6
 8002a62:	e7bb      	b.n	80029dc <HAL_FLASH_Program+0x20>
 8002a64:	20000070 	.word	0x20000070
 8002a68:	40022000 	.word	0x40022000

08002a6c <HAL_FLASH_Program_IT>:
 8002a6c:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 8002a70:	4606      	mov	r6, r0
 8002a72:	460f      	mov	r7, r1
 8002a74:	4614      	mov	r4, r2
 8002a76:	461d      	mov	r5, r3
 8002a78:	f04f 0800 	mov.w	r8, #0
 8002a7c:	4812      	ldr	r0, [pc, #72]	@ (8002ac8 <HAL_FLASH_Program_IT+0x5c>)
 8002a7e:	6900      	ldr	r0, [r0, #16]
 8002a80:	f440 50a0 	orr.w	r0, r0, #5120	@ 0x1400
 8002a84:	4910      	ldr	r1, [pc, #64]	@ (8002ac8 <HAL_FLASH_Program_IT+0x5c>)
 8002a86:	6108      	str	r0, [r1, #16]
 8002a88:	4810      	ldr	r0, [pc, #64]	@ (8002acc <HAL_FLASH_Program_IT+0x60>)
 8002a8a:	6087      	str	r7, [r0, #8]
 8002a8c:	6104      	str	r4, [r0, #16]
 8002a8e:	6145      	str	r5, [r0, #20]
 8002a90:	2e01      	cmp	r6, #1
 8002a92:	d105      	bne.n	8002aa0 <HAL_FLASH_Program_IT+0x34>
 8002a94:	2003      	movs	r0, #3
 8002a96:	490d      	ldr	r1, [pc, #52]	@ (8002acc <HAL_FLASH_Program_IT+0x60>)
 8002a98:	7008      	strb	r0, [r1, #0]
 8002a9a:	2001      	movs	r0, #1
 8002a9c:	6048      	str	r0, [r1, #4]
 8002a9e:	e00c      	b.n	8002aba <HAL_FLASH_Program_IT+0x4e>
 8002aa0:	2e02      	cmp	r6, #2
 8002aa2:	d105      	bne.n	8002ab0 <HAL_FLASH_Program_IT+0x44>
 8002aa4:	2004      	movs	r0, #4
 8002aa6:	4909      	ldr	r1, [pc, #36]	@ (8002acc <HAL_FLASH_Program_IT+0x60>)
 8002aa8:	7008      	strb	r0, [r1, #0]
 8002aaa:	2002      	movs	r0, #2
 8002aac:	6048      	str	r0, [r1, #4]
 8002aae:	e004      	b.n	8002aba <HAL_FLASH_Program_IT+0x4e>
 8002ab0:	2005      	movs	r0, #5
 8002ab2:	4906      	ldr	r1, [pc, #24]	@ (8002acc <HAL_FLASH_Program_IT+0x60>)
 8002ab4:	7008      	strb	r0, [r1, #0]
 8002ab6:	2004      	movs	r0, #4
 8002ab8:	6048      	str	r0, [r1, #4]
 8002aba:	b2a1      	uxth	r1, r4
 8002abc:	4638      	mov	r0, r7
 8002abe:	f7fe fb9d 	bl	80011fc <FLASH_Program_HalfWord>
 8002ac2:	4640      	mov	r0, r8
 8002ac4:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
 8002ac8:	40022000 	.word	0x40022000
 8002acc:	20000070 	.word	0x20000070

08002ad0 <HAL_FLASH_Unlock>:
 8002ad0:	2000      	movs	r0, #0
 8002ad2:	4908      	ldr	r1, [pc, #32]	@ (8002af4 <HAL_FLASH_Unlock+0x24>)
 8002ad4:	6909      	ldr	r1, [r1, #16]
 8002ad6:	f001 0180 	and.w	r1, r1, #128	@ 0x80
 8002ada:	b151      	cbz	r1, 8002af2 <HAL_FLASH_Unlock+0x22>
 8002adc:	4906      	ldr	r1, [pc, #24]	@ (8002af8 <HAL_FLASH_Unlock+0x28>)
 8002ade:	4a05      	ldr	r2, [pc, #20]	@ (8002af4 <HAL_FLASH_Unlock+0x24>)
 8002ae0:	6051      	str	r1, [r2, #4]
 8002ae2:	4906      	ldr	r1, [pc, #24]	@ (8002afc <HAL_FLASH_Unlock+0x2c>)
 8002ae4:	6051      	str	r1, [r2, #4]
 8002ae6:	4611      	mov	r1, r2
 8002ae8:	6909      	ldr	r1, [r1, #16]
 8002aea:	f001 0180 	and.w	r1, r1, #128	@ 0x80
 8002aee:	b101      	cbz	r1, 8002af2 <HAL_FLASH_Unlock+0x22>
 8002af0:	2001      	movs	r0, #1
 8002af2:	4770      	bx	lr
 8002af4:	40022000 	.word	0x40022000
 8002af8:	45670123 	.word	0x45670123
 8002afc:	cdef89ab 	.word	0xcdef89ab

08002b00 <HAL_GPIOEx_ConfigEventout>:
 8002b00:	4a04      	ldr	r2, [pc, #16]	@ (8002b14 <HAL_GPIOEx_ConfigEventout+0x14>)
 8002b02:	6812      	ldr	r2, [r2, #0]
 8002b04:	f022 027f 	bic.w	r2, r2, #127	@ 0x7f
 8002b08:	ea40 0301 	orr.w	r3, r0, r1
 8002b0c:	431a      	orrs	r2, r3
 8002b0e:	4b01      	ldr	r3, [pc, #4]	@ (8002b14 <HAL_GPIOEx_ConfigEventout+0x14>)
 8002b10:	601a      	str	r2, [r3, #0]
 8002b12:	4770      	bx	lr
 8002b14:	40010000 	.word	0x40010000

08002b18 <HAL_GPIOEx_DisableEventout>:
 8002b18:	4803      	ldr	r0, [pc, #12]	@ (8002b28 <HAL_GPIOEx_DisableEventout+0x10>)
 8002b1a:	6800      	ldr	r0, [r0, #0]
 8002b1c:	f020 0080 	bic.w	r0, r0, #128	@ 0x80
 8002b20:	4901      	ldr	r1, [pc, #4]	@ (8002b28 <HAL_GPIOEx_DisableEventout+0x10>)
 8002b22:	6008      	str	r0, [r1, #0]
 8002b24:	4770      	bx	lr
 8002b26:	0000      	.short	0x0000
 8002b28:	40010000 	.word	0x40010000

08002b2c <HAL_GPIOEx_EnableEventout>:
 8002b2c:	4803      	ldr	r0, [pc, #12]	@ (8002b3c <HAL_GPIOEx_EnableEventout+0x10>)
 8002b2e:	6800      	ldr	r0, [r0, #0]
 8002b30:	f040 0080 	orr.w	r0, r0, #128	@ 0x80
 8002b34:	4901      	ldr	r1, [pc, #4]	@ (8002b3c <HAL_GPIOEx_EnableEventout+0x10>)
 8002b36:	6008      	str	r0, [r1, #0]
 8002b38:	4770      	bx	lr
 8002b3a:	0000      	.short	0x0000
 8002b3c:	40010000 	.word	0x40010000

08002b40 <HAL_GPIO_DeInit>:
 8002b40:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 8002b44:	4602      	mov	r2, r0
 8002b46:	460b      	mov	r3, r1
 8002b48:	2000      	movs	r0, #0
 8002b4a:	e08c      	b.n	8002c66 <HAL_GPIO_DeInit+0x126>
 8002b4c:	2701      	movs	r7, #1
 8002b4e:	4087      	lsls	r7, r0
 8002b50:	ea07 0103 	and.w	r1, r7, r3
 8002b54:	2900      	cmp	r1, #0
 8002b56:	d06f      	beq.n	8002c38 <HAL_GPIO_DeInit+0xf8>
 8002b58:	4f46      	ldr	r7, [pc, #280]	@ (8002c74 <HAL_GPIO_DeInit+0x134>)
 8002b5a:	ea4f 0c90 	mov.w	ip, r0, lsr #2
 8002b5e:	f857 402c 	ldr.w	r4, [r7, ip, lsl #2]
 8002b62:	0787      	lsls	r7, r0, #30
 8002b64:	ea4f 7c17 	mov.w	ip, r7, lsr #28
 8002b68:	270f      	movs	r7, #15
 8002b6a:	fa07 f70c 	lsl.w	r7, r7, ip
 8002b6e:	403c      	ands	r4, r7
 8002b70:	4f41      	ldr	r7, [pc, #260]	@ (8002c78 <HAL_GPIO_DeInit+0x138>)
 8002b72:	42ba      	cmp	r2, r7
 8002b74:	d101      	bne.n	8002b7a <HAL_GPIO_DeInit+0x3a>
 8002b76:	2700      	movs	r7, #0
 8002b78:	e019      	b.n	8002bae <HAL_GPIO_DeInit+0x6e>
 8002b7a:	4f40      	ldr	r7, [pc, #256]	@ (8002c7c <HAL_GPIO_DeInit+0x13c>)
 8002b7c:	42ba      	cmp	r2, r7
 8002b7e:	d101      	bne.n	8002b84 <HAL_GPIO_DeInit+0x44>
 8002b80:	2701      	movs	r7, #1
 8002b82:	e014      	b.n	8002bae <HAL_GPIO_DeInit+0x6e>
 8002b84:	4f3e      	ldr	r7, [pc, #248]	@ (8002c80 <HAL_GPIO_DeInit+0x140>)
 8002b86:	42ba      	cmp	r2, r7
 8002b88:	d101      	bne.n	8002b8e <HAL_GPIO_DeInit+0x4e>
 8002b8a:	2702      	movs	r7, #2
 8002b8c:	e00f      	b.n	8002bae <HAL_GPIO_DeInit+0x6e>
 8002b8e:	4f3d      	ldr	r7, [pc, #244]	@ (8002c84 <HAL_GPIO_DeInit+0x144>)
 8002b90:	42ba      	cmp	r2, r7
 8002b92:	d101      	bne.n	8002b98 <HAL_GPIO_DeInit+0x58>
 8002b94:	2703      	movs	r7, #3
 8002b96:	e00a      	b.n	8002bae <HAL_GPIO_DeInit+0x6e>
 8002b98:	4f3b      	ldr	r7, [pc, #236]	@ (8002c88 <HAL_GPIO_DeInit+0x148>)
 8002b9a:	42ba      	cmp	r2, r7
 8002b9c:	d101      	bne.n	8002ba2 <HAL_GPIO_DeInit+0x62>
 8002b9e:	2704      	movs	r7, #4
 8002ba0:	e005      	b.n	8002bae <HAL_GPIO_DeInit+0x6e>
 8002ba2:	4f3a      	ldr	r7, [pc, #232]	@ (8002c8c <HAL_GPIO_DeInit+0x14c>)
 8002ba4:	42ba      	cmp	r2, r7
 8002ba6:	d101      	bne.n	8002bac <HAL_GPIO_DeInit+0x6c>
 8002ba8:	2705      	movs	r7, #5
 8002baa:	e000      	b.n	8002bae <HAL_GPIO_DeInit+0x6e>
 8002bac:	2706      	movs	r7, #6
 8002bae:	ea4f 7c80 	mov.w	ip, r0, lsl #30
 8002bb2:	ea4f 7c1c 	mov.w	ip, ip, lsr #28
 8002bb6:	fa07 f70c 	lsl.w	r7, r7, ip
 8002bba:	42a7      	cmp	r7, r4
 8002bbc:	d132      	bne.n	8002c24 <HAL_GPIO_DeInit+0xe4>
 8002bbe:	4f34      	ldr	r7, [pc, #208]	@ (8002c90 <HAL_GPIO_DeInit+0x150>)
 8002bc0:	683f      	ldr	r7, [r7, #0]
 8002bc2:	438f      	bics	r7, r1
 8002bc4:	f8df c0c8 	ldr.w	ip, [pc, #200]	@ 8002c90 <HAL_GPIO_DeInit+0x150>
 8002bc8:	f8cc 7000 	str.w	r7, [ip]
 8002bcc:	f10c 0704 	add.w	r7, ip, #4
 8002bd0:	683f      	ldr	r7, [r7, #0]
 8002bd2:	438f      	bics	r7, r1
 8002bd4:	f10c 0c04 	add.w	ip, ip, #4
 8002bd8:	f8cc 7000 	str.w	r7, [ip]
 8002bdc:	4f2c      	ldr	r7, [pc, #176]	@ (8002c90 <HAL_GPIO_DeInit+0x150>)
 8002bde:	370c      	adds	r7, #12
 8002be0:	683f      	ldr	r7, [r7, #0]
 8002be2:	438f      	bics	r7, r1
 8002be4:	f8df c0a8 	ldr.w	ip, [pc, #168]	@ 8002c90 <HAL_GPIO_DeInit+0x150>
 8002be8:	f10c 0c0c 	add.w	ip, ip, #12
 8002bec:	f8cc 7000 	str.w	r7, [ip]
 8002bf0:	f1ac 0704 	sub.w	r7, ip, #4
 8002bf4:	683f      	ldr	r7, [r7, #0]
 8002bf6:	438f      	bics	r7, r1
 8002bf8:	f1ac 0c04 	sub.w	ip, ip, #4
 8002bfc:	f8cc 7000 	str.w	r7, [ip]
 8002c00:	0787      	lsls	r7, r0, #30
 8002c02:	ea4f 7c17 	mov.w	ip, r7, lsr #28
 8002c06:	270f      	movs	r7, #15
 8002c08:	fa07 f40c 	lsl.w	r4, r7, ip
 8002c0c:	4f19      	ldr	r7, [pc, #100]	@ (8002c74 <HAL_GPIO_DeInit+0x134>)
 8002c0e:	ea4f 0c90 	mov.w	ip, r0, lsr #2
 8002c12:	f857 702c 	ldr.w	r7, [r7, ip, lsl #2]
 8002c16:	43a7      	bics	r7, r4
 8002c18:	f8df c058 	ldr.w	ip, [pc, #88]	@ 8002c74 <HAL_GPIO_DeInit+0x134>
 8002c1c:	ea4f 0890 	mov.w	r8, r0, lsr #2
 8002c20:	f84c 7028 	str.w	r7, [ip, r8, lsl #2]
 8002c24:	29ff      	cmp	r1, #255	@ 0xff
 8002c26:	d801      	bhi.n	8002c2c <HAL_GPIO_DeInit+0xec>
 8002c28:	4617      	mov	r7, r2
 8002c2a:	e000      	b.n	8002c2e <HAL_GPIO_DeInit+0xee>
 8002c2c:	1d17      	adds	r7, r2, #4
 8002c2e:	463d      	mov	r5, r7
 8002c30:	29ff      	cmp	r1, #255	@ 0xff
 8002c32:	d802      	bhi.n	8002c3a <HAL_GPIO_DeInit+0xfa>
 8002c34:	0087      	lsls	r7, r0, #2
 8002c36:	e003      	b.n	8002c40 <HAL_GPIO_DeInit+0x100>
 8002c38:	e014      	b.n	8002c64 <HAL_GPIO_DeInit+0x124>
 8002c3a:	f1a0 0708 	sub.w	r7, r0, #8
 8002c3e:	00bf      	lsls	r7, r7, #2
 8002c40:	463e      	mov	r6, r7
 8002c42:	682f      	ldr	r7, [r5, #0]
 8002c44:	f04f 0c0f 	mov.w	ip, #15
 8002c48:	fa0c fc06 	lsl.w	ip, ip, r6
 8002c4c:	ea27 070c 	bic.w	r7, r7, ip
 8002c50:	f04f 0c04 	mov.w	ip, #4
 8002c54:	fa0c fc06 	lsl.w	ip, ip, r6
 8002c58:	ea47 070c 	orr.w	r7, r7, ip
 8002c5c:	602f      	str	r7, [r5, #0]
 8002c5e:	68d7      	ldr	r7, [r2, #12]
 8002c60:	438f      	bics	r7, r1
 8002c62:	60d7      	str	r7, [r2, #12]
 8002c64:	1c40      	adds	r0, r0, #1
 8002c66:	fa23 f700 	lsr.w	r7, r3, r0
 8002c6a:	2f00      	cmp	r7, #0
 8002c6c:	f47f af6e 	bne.w	8002b4c <HAL_GPIO_DeInit+0xc>
 8002c70:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
 8002c74:	40010008 	.word	0x40010008
 8002c78:	40010800 	.word	0x40010800
 8002c7c:	40010c00 	.word	0x40010c00
 8002c80:	40011000 	.word	0x40011000
 8002c84:	40011400 	.word	0x40011400
 8002c88:	40011800 	.word	0x40011800
 8002c8c:	40011c00 	.word	0x40011c00
 8002c90:	40010400 	.word	0x40010400

08002c94 <HAL_GPIO_EXTI_Callback>:
 8002c94:	4770      	bx	lr
	...

08002c98 <HAL_GPIO_EXTI_IRQHandler>:
 8002c98:	b510      	push	{r4, lr}
 8002c9a:	4604      	mov	r4, r0
 8002c9c:	4804      	ldr	r0, [pc, #16]	@ (8002cb0 <HAL_GPIO_EXTI_IRQHandler+0x18>)
 8002c9e:	6800      	ldr	r0, [r0, #0]
 8002ca0:	4020      	ands	r0, r4
 8002ca2:	b120      	cbz	r0, 8002cae <HAL_GPIO_EXTI_IRQHandler+0x16>
 8002ca4:	4802      	ldr	r0, [pc, #8]	@ (8002cb0 <HAL_GPIO_EXTI_IRQHandler+0x18>)
 8002ca6:	6004      	str	r4, [r0, #0]
 8002ca8:	4620      	mov	r0, r4
 8002caa:	f7ff fff3 	bl	8002c94 <HAL_GPIO_EXTI_Callback>
 8002cae:	bd10      	pop	{r4, pc}
 8002cb0:	40010414 	.word	0x40010414

08002cb4 <HAL_GPIO_Init>:
 8002cb4:	e92d 47f8 	stmdb	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, lr}
 8002cb8:	4602      	mov	r2, r0
 8002cba:	2300      	movs	r3, #0
 8002cbc:	469c      	mov	ip, r3
 8002cbe:	e17b      	b.n	8002fb8 <HAL_GPIO_Init+0x304>
 8002cc0:	f04f 0801 	mov.w	r8, #1
 8002cc4:	fa08 f403 	lsl.w	r4, r8, r3
 8002cc8:	f8d1 8000 	ldr.w	r8, [r1]
 8002ccc:	ea08 0004 	and.w	r0, r8, r4
 8002cd0:	42a0      	cmp	r0, r4
 8002cd2:	d17d      	bne.n	8002dd0 <HAL_GPIO_Init+0x11c>
 8002cd4:	f8df a2f4 	ldr.w	sl, [pc, #756]	@ 8002fcc <HAL_GPIO_Init+0x318>
 8002cd8:	f8d1 8004 	ldr.w	r8, [r1, #4]
 8002cdc:	eba8 090a 	sub.w	r9, r8, sl
 8002ce0:	45d0      	cmp	r8, sl
 8002ce2:	d03a      	beq.n	8002d5a <HAL_GPIO_Init+0xa6>
 8002ce4:	dc14      	bgt.n	8002d10 <HAL_GPIO_Init+0x5c>
 8002ce6:	f1b8 0f03 	cmp.w	r8, #3
 8002cea:	d050      	beq.n	8002d8e <HAL_GPIO_Init+0xda>
 8002cec:	dc09      	bgt.n	8002d02 <HAL_GPIO_Init+0x4e>
 8002cee:	f1b8 0f00 	cmp.w	r8, #0
 8002cf2:	d031      	beq.n	8002d58 <HAL_GPIO_Init+0xa4>
 8002cf4:	f1b8 0f01 	cmp.w	r8, #1
 8002cf8:	d01c      	beq.n	8002d34 <HAL_GPIO_Init+0x80>
 8002cfa:	f1b8 0f02 	cmp.w	r8, #2
 8002cfe:	d149      	bne.n	8002d94 <HAL_GPIO_Init+0xe0>
 8002d00:	e020      	b.n	8002d44 <HAL_GPIO_Init+0x90>
 8002d02:	f1b8 0f11 	cmp.w	r8, #17
 8002d06:	d018      	beq.n	8002d3a <HAL_GPIO_Init+0x86>
 8002d08:	f1b8 0f12 	cmp.w	r8, #18
 8002d0c:	d142      	bne.n	8002d94 <HAL_GPIO_Init+0xe0>
 8002d0e:	e01e      	b.n	8002d4e <HAL_GPIO_Init+0x9a>
 8002d10:	f5b9 1f88 	cmp.w	r9, #1114112	@ 0x110000
 8002d14:	d025      	beq.n	8002d62 <HAL_GPIO_Init+0xae>
 8002d16:	dc06      	bgt.n	8002d26 <HAL_GPIO_Init+0x72>
 8002d18:	f5b9 3f80 	cmp.w	r9, #65536	@ 0x10000
 8002d1c:	d020      	beq.n	8002d60 <HAL_GPIO_Init+0xac>
 8002d1e:	f5b9 1f80 	cmp.w	r9, #1048576	@ 0x100000
 8002d22:	d137      	bne.n	8002d94 <HAL_GPIO_Init+0xe0>
 8002d24:	e01a      	b.n	8002d5c <HAL_GPIO_Init+0xa8>
 8002d26:	f5b9 1f00 	cmp.w	r9, #2097152	@ 0x200000
 8002d2a:	d018      	beq.n	8002d5e <HAL_GPIO_Init+0xaa>
 8002d2c:	f5b9 1f04 	cmp.w	r9, #2162688	@ 0x210000
 8002d30:	d130      	bne.n	8002d94 <HAL_GPIO_Init+0xe0>
 8002d32:	e017      	b.n	8002d64 <HAL_GPIO_Init+0xb0>
 8002d34:	f8d1 c00c 	ldr.w	ip, [r1, #12]
 8002d38:	e02d      	b.n	8002d96 <HAL_GPIO_Init+0xe2>
 8002d3a:	f8d1 800c 	ldr.w	r8, [r1, #12]
 8002d3e:	f108 0c04 	add.w	ip, r8, #4
 8002d42:	e028      	b.n	8002d96 <HAL_GPIO_Init+0xe2>
 8002d44:	f8d1 800c 	ldr.w	r8, [r1, #12]
 8002d48:	f108 0c08 	add.w	ip, r8, #8
 8002d4c:	e023      	b.n	8002d96 <HAL_GPIO_Init+0xe2>
 8002d4e:	f8d1 800c 	ldr.w	r8, [r1, #12]
 8002d52:	f108 0c0c 	add.w	ip, r8, #12
 8002d56:	e01e      	b.n	8002d96 <HAL_GPIO_Init+0xe2>
 8002d58:	bf00      	nop
 8002d5a:	bf00      	nop
 8002d5c:	bf00      	nop
 8002d5e:	bf00      	nop
 8002d60:	bf00      	nop
 8002d62:	bf00      	nop
 8002d64:	f8d1 8008 	ldr.w	r8, [r1, #8]
 8002d68:	f1b8 0f00 	cmp.w	r8, #0
 8002d6c:	d102      	bne.n	8002d74 <HAL_GPIO_Init+0xc0>
 8002d6e:	f04f 0c04 	mov.w	ip, #4
 8002d72:	e00b      	b.n	8002d8c <HAL_GPIO_Init+0xd8>
 8002d74:	f8d1 8008 	ldr.w	r8, [r1, #8]
 8002d78:	f1b8 0f01 	cmp.w	r8, #1
 8002d7c:	d103      	bne.n	8002d86 <HAL_GPIO_Init+0xd2>
 8002d7e:	f04f 0c08 	mov.w	ip, #8
 8002d82:	6114      	str	r4, [r2, #16]
 8002d84:	e002      	b.n	8002d8c <HAL_GPIO_Init+0xd8>
 8002d86:	f04f 0c08 	mov.w	ip, #8
 8002d8a:	6154      	str	r4, [r2, #20]
 8002d8c:	e003      	b.n	8002d96 <HAL_GPIO_Init+0xe2>
 8002d8e:	f04f 0c00 	mov.w	ip, #0
 8002d92:	e000      	b.n	8002d96 <HAL_GPIO_Init+0xe2>
 8002d94:	bf00      	nop
 8002d96:	bf00      	nop
 8002d98:	28ff      	cmp	r0, #255	@ 0xff
 8002d9a:	d801      	bhi.n	8002da0 <HAL_GPIO_Init+0xec>
 8002d9c:	4690      	mov	r8, r2
 8002d9e:	e001      	b.n	8002da4 <HAL_GPIO_Init+0xf0>
 8002da0:	f102 0804 	add.w	r8, r2, #4
 8002da4:	4646      	mov	r6, r8
 8002da6:	28ff      	cmp	r0, #255	@ 0xff
 8002da8:	d802      	bhi.n	8002db0 <HAL_GPIO_Init+0xfc>
 8002daa:	ea4f 0883 	mov.w	r8, r3, lsl #2
 8002dae:	e003      	b.n	8002db8 <HAL_GPIO_Init+0x104>
 8002db0:	f1a3 0808 	sub.w	r8, r3, #8
 8002db4:	ea4f 0888 	mov.w	r8, r8, lsl #2
 8002db8:	4647      	mov	r7, r8
 8002dba:	f8d6 8000 	ldr.w	r8, [r6]
 8002dbe:	f04f 090f 	mov.w	r9, #15
 8002dc2:	fa09 f907 	lsl.w	r9, r9, r7
 8002dc6:	ea28 0809 	bic.w	r8, r8, r9
 8002dca:	fa0c f907 	lsl.w	r9, ip, r7
 8002dce:	e000      	b.n	8002dd2 <HAL_GPIO_Init+0x11e>
 8002dd0:	e07a      	b.n	8002ec8 <HAL_GPIO_Init+0x214>
 8002dd2:	ea48 0809 	orr.w	r8, r8, r9
 8002dd6:	f8c6 8000 	str.w	r8, [r6]
 8002dda:	f8d1 8004 	ldr.w	r8, [r1, #4]
 8002dde:	f008 5880 	and.w	r8, r8, #268435456	@ 0x10000000
 8002de2:	f1b8 5f80 	cmp.w	r8, #268435456	@ 0x10000000
 8002de6:	d16f      	bne.n	8002ec8 <HAL_GPIO_Init+0x214>
 8002de8:	bf00      	nop
 8002dea:	f8df 81e4 	ldr.w	r8, [pc, #484]	@ 8002fd0 <HAL_GPIO_Init+0x31c>
 8002dee:	f8d8 8018 	ldr.w	r8, [r8, #24]
 8002df2:	f048 0801 	orr.w	r8, r8, #1
 8002df6:	f8df 91d8 	ldr.w	r9, [pc, #472]	@ 8002fd0 <HAL_GPIO_Init+0x31c>
 8002dfa:	f8c9 8018 	str.w	r8, [r9, #24]
 8002dfe:	46c8      	mov	r8, r9
 8002e00:	f8d8 8018 	ldr.w	r8, [r8, #24]
 8002e04:	f008 0801 	and.w	r8, r8, #1
 8002e08:	f8cd 8000 	str.w	r8, [sp]
 8002e0c:	bf00      	nop
 8002e0e:	bf00      	nop
 8002e10:	ea4f 38b9 	mov.w	r8, r9, ror #14
 8002e14:	ea4f 0993 	mov.w	r9, r3, lsr #2
 8002e18:	f858 5029 	ldr.w	r5, [r8, r9, lsl #2]
 8002e1c:	ea4f 7883 	mov.w	r8, r3, lsl #30
 8002e20:	ea4f 7918 	mov.w	r9, r8, lsr #28
 8002e24:	f04f 080f 	mov.w	r8, #15
 8002e28:	fa08 f809 	lsl.w	r8, r8, r9
 8002e2c:	ea25 0508 	bic.w	r5, r5, r8
 8002e30:	f8df 81a0 	ldr.w	r8, [pc, #416]	@ 8002fd4 <HAL_GPIO_Init+0x320>
 8002e34:	4542      	cmp	r2, r8
 8002e36:	d102      	bne.n	8002e3e <HAL_GPIO_Init+0x18a>
 8002e38:	f04f 0800 	mov.w	r8, #0
 8002e3c:	e024      	b.n	8002e88 <HAL_GPIO_Init+0x1d4>
 8002e3e:	f8df 8198 	ldr.w	r8, [pc, #408]	@ 8002fd8 <HAL_GPIO_Init+0x324>
 8002e42:	4542      	cmp	r2, r8
 8002e44:	d102      	bne.n	8002e4c <HAL_GPIO_Init+0x198>
 8002e46:	f04f 0801 	mov.w	r8, #1
 8002e4a:	e01d      	b.n	8002e88 <HAL_GPIO_Init+0x1d4>
 8002e4c:	f8df 818c 	ldr.w	r8, [pc, #396]	@ 8002fdc <HAL_GPIO_Init+0x328>
 8002e50:	4542      	cmp	r2, r8
 8002e52:	d102      	bne.n	8002e5a <HAL_GPIO_Init+0x1a6>
 8002e54:	f04f 0802 	mov.w	r8, #2
 8002e58:	e016      	b.n	8002e88 <HAL_GPIO_Init+0x1d4>
 8002e5a:	f8df 8184 	ldr.w	r8, [pc, #388]	@ 8002fe0 <HAL_GPIO_Init+0x32c>
 8002e5e:	4542      	cmp	r2, r8
 8002e60:	d102      	bne.n	8002e68 <HAL_GPIO_Init+0x1b4>
 8002e62:	f04f 0803 	mov.w	r8, #3
 8002e66:	e00f      	b.n	8002e88 <HAL_GPIO_Init+0x1d4>
 8002e68:	f8df 8178 	ldr.w	r8, [pc, #376]	@ 8002fe4 <HAL_GPIO_Init+0x330>
 8002e6c:	4542      	cmp	r2, r8
 8002e6e:	d102      	bne.n	8002e76 <HAL_GPIO_Init+0x1c2>
 8002e70:	f04f 0804 	mov.w	r8, #4
 8002e74:	e008      	b.n	8002e88 <HAL_GPIO_Init+0x1d4>
 8002e76:	f8df 8170 	ldr.w	r8, [pc, #368]	@ 8002fe8 <HAL_GPIO_Init+0x334>
 8002e7a:	4542      	cmp	r2, r8
 8002e7c:	d102      	bne.n	8002e84 <HAL_GPIO_Init+0x1d0>
 8002e7e:	f04f 0805 	mov.w	r8, #5
 8002e82:	e001      	b.n	8002e88 <HAL_GPIO_Init+0x1d4>
 8002e84:	f04f 0806 	mov.w	r8, #6
 8002e88:	ea4f 7983 	mov.w	r9, r3, lsl #30
 8002e8c:	ea4f 7919 	mov.w	r9, r9, lsr #28
 8002e90:	fa08 f809 	lsl.w	r8, r8, r9
 8002e94:	ea48 0505 	orr.w	r5, r8, r5
 8002e98:	f8df 8150 	ldr.w	r8, [pc, #336]	@ 8002fec <HAL_GPIO_Init+0x338>
 8002e9c:	ea4f 0993 	mov.w	r9, r3, lsr #2
 8002ea0:	f848 5029 	str.w	r5, [r8, r9, lsl #2]
 8002ea4:	f8d1 8004 	ldr.w	r8, [r1, #4]
 8002ea8:	f408 1880 	and.w	r8, r8, #1048576	@ 0x100000
 8002eac:	f5b8 1f80 	cmp.w	r8, #1048576	@ 0x100000
 8002eb0:	d10b      	bne.n	8002eca <HAL_GPIO_Init+0x216>
 8002eb2:	f8df 813c 	ldr.w	r8, [pc, #316]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002eb6:	f8d8 8000 	ldr.w	r8, [r8]
 8002eba:	ea48 0800 	orr.w	r8, r8, r0
 8002ebe:	f8df 9130 	ldr.w	r9, [pc, #304]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002ec2:	f8c9 8000 	str.w	r8, [r9]
 8002ec6:	e00a      	b.n	8002ede <HAL_GPIO_Init+0x22a>
 8002ec8:	e075      	b.n	8002fb6 <HAL_GPIO_Init+0x302>
 8002eca:	f8df 8124 	ldr.w	r8, [pc, #292]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002ece:	f8d8 8000 	ldr.w	r8, [r8]
 8002ed2:	ea28 0800 	bic.w	r8, r8, r0
 8002ed6:	f8df 9118 	ldr.w	r9, [pc, #280]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002eda:	f8c9 8000 	str.w	r8, [r9]
 8002ede:	f8d1 8004 	ldr.w	r8, [r1, #4]
 8002ee2:	f408 1800 	and.w	r8, r8, #2097152	@ 0x200000
 8002ee6:	f5b8 1f00 	cmp.w	r8, #2097152	@ 0x200000
 8002eea:	d10e      	bne.n	8002f0a <HAL_GPIO_Init+0x256>
 8002eec:	f8df 8100 	ldr.w	r8, [pc, #256]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002ef0:	f108 0804 	add.w	r8, r8, #4
 8002ef4:	f8d8 8000 	ldr.w	r8, [r8]
 8002ef8:	ea48 0800 	orr.w	r8, r8, r0
 8002efc:	f8df 90f0 	ldr.w	r9, [pc, #240]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f00:	f109 0904 	add.w	r9, r9, #4
 8002f04:	f8c9 8000 	str.w	r8, [r9]
 8002f08:	e00d      	b.n	8002f26 <HAL_GPIO_Init+0x272>
 8002f0a:	f8df 80e4 	ldr.w	r8, [pc, #228]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f0e:	f108 0804 	add.w	r8, r8, #4
 8002f12:	f8d8 8000 	ldr.w	r8, [r8]
 8002f16:	ea28 0800 	bic.w	r8, r8, r0
 8002f1a:	f8df 90d4 	ldr.w	r9, [pc, #212]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f1e:	f109 0904 	add.w	r9, r9, #4
 8002f22:	f8c9 8000 	str.w	r8, [r9]
 8002f26:	f8d1 8004 	ldr.w	r8, [r1, #4]
 8002f2a:	f408 3800 	and.w	r8, r8, #131072	@ 0x20000
 8002f2e:	f5b8 3f00 	cmp.w	r8, #131072	@ 0x20000
 8002f32:	d10e      	bne.n	8002f52 <HAL_GPIO_Init+0x29e>
 8002f34:	f8df 80b8 	ldr.w	r8, [pc, #184]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f38:	f1a8 0804 	sub.w	r8, r8, #4
 8002f3c:	f8d8 8000 	ldr.w	r8, [r8]
 8002f40:	ea48 0800 	orr.w	r8, r8, r0
 8002f44:	f8df 90a8 	ldr.w	r9, [pc, #168]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f48:	f1a9 0904 	sub.w	r9, r9, #4
 8002f4c:	f8c9 8000 	str.w	r8, [r9]
 8002f50:	e00d      	b.n	8002f6e <HAL_GPIO_Init+0x2ba>
 8002f52:	f8df 809c 	ldr.w	r8, [pc, #156]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f56:	f1a8 0804 	sub.w	r8, r8, #4
 8002f5a:	f8d8 8000 	ldr.w	r8, [r8]
 8002f5e:	ea28 0800 	bic.w	r8, r8, r0
 8002f62:	f8df 908c 	ldr.w	r9, [pc, #140]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f66:	f1a9 0904 	sub.w	r9, r9, #4
 8002f6a:	f8c9 8000 	str.w	r8, [r9]
 8002f6e:	f8d1 8004 	ldr.w	r8, [r1, #4]
 8002f72:	f408 3880 	and.w	r8, r8, #65536	@ 0x10000
 8002f76:	f5b8 3f80 	cmp.w	r8, #65536	@ 0x10000
 8002f7a:	d10e      	bne.n	8002f9a <HAL_GPIO_Init+0x2e6>
 8002f7c:	f8df 8070 	ldr.w	r8, [pc, #112]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f80:	f1a8 0808 	sub.w	r8, r8, #8
 8002f84:	f8d8 8000 	ldr.w	r8, [r8]
 8002f88:	ea48 0800 	orr.w	r8, r8, r0
 8002f8c:	f8df 9060 	ldr.w	r9, [pc, #96]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f90:	f1a9 0908 	sub.w	r9, r9, #8
 8002f94:	f8c9 8000 	str.w	r8, [r9]
 8002f98:	e00d      	b.n	8002fb6 <HAL_GPIO_Init+0x302>
 8002f9a:	f8df 8054 	ldr.w	r8, [pc, #84]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002f9e:	f1a8 0808 	sub.w	r8, r8, #8
 8002fa2:	f8d8 8000 	ldr.w	r8, [r8]
 8002fa6:	ea28 0800 	bic.w	r8, r8, r0
 8002faa:	f8df 9044 	ldr.w	r9, [pc, #68]	@ 8002ff0 <HAL_GPIO_Init+0x33c>
 8002fae:	f1a9 0908 	sub.w	r9, r9, #8
 8002fb2:	f8c9 8000 	str.w	r8, [r9]
 8002fb6:	1c5b      	adds	r3, r3, #1
 8002fb8:	f8d1 8000 	ldr.w	r8, [r1]
 8002fbc:	fa28 f803 	lsr.w	r8, r8, r3
 8002fc0:	f1b8 0f00 	cmp.w	r8, #0
 8002fc4:	f47f ae7c 	bne.w	8002cc0 <HAL_GPIO_Init+0xc>
 8002fc8:	e8bd 87f8 	ldmia.w	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, pc}
 8002fcc:	10110000 	.word	0x10110000
 8002fd0:	40021000 	.word	0x40021000
 8002fd4:	40010800 	.word	0x40010800
 8002fd8:	40010c00 	.word	0x40010c00
 8002fdc:	40011000 	.word	0x40011000
 8002fe0:	40011400 	.word	0x40011400
 8002fe4:	40011800 	.word	0x40011800
 8002fe8:	40011c00 	.word	0x40011c00
 8002fec:	40010008 	.word	0x40010008
 8002ff0:	40010408 	.word	0x40010408

08002ff4 <HAL_GPIO_LockPin>:
 8002ff4:	b508      	push	{r3, lr}
 8002ff6:	4602      	mov	r2, r0
 8002ff8:	f44f 3080 	mov.w	r0, #65536	@ 0x10000
 8002ffc:	9000      	str	r0, [sp, #0]
 8002ffe:	9800      	ldr	r0, [sp, #0]
 8003000:	4308      	orrs	r0, r1
 8003002:	9000      	str	r0, [sp, #0]
 8003004:	9800      	ldr	r0, [sp, #0]
 8003006:	6190      	str	r0, [r2, #24]
 8003008:	6191      	str	r1, [r2, #24]
 800300a:	9800      	ldr	r0, [sp, #0]
 800300c:	6190      	str	r0, [r2, #24]
 800300e:	6990      	ldr	r0, [r2, #24]
 8003010:	9000      	str	r0, [sp, #0]
 8003012:	6990      	ldr	r0, [r2, #24]
 8003014:	f400 3080 	and.w	r0, r0, #65536	@ 0x10000
 8003018:	b108      	cbz	r0, 800301e <HAL_GPIO_LockPin+0x2a>
 800301a:	2000      	movs	r0, #0
 800301c:	bd08      	pop	{r3, pc}
 800301e:	2001      	movs	r0, #1
 8003020:	e7fc      	b.n	800301c <HAL_GPIO_LockPin+0x28>

08003022 <HAL_GPIO_ReadPin>:
 8003022:	4602      	mov	r2, r0
 8003024:	6893      	ldr	r3, [r2, #8]
 8003026:	400b      	ands	r3, r1
 8003028:	b10b      	cbz	r3, 800302e <HAL_GPIO_ReadPin+0xc>
 800302a:	2001      	movs	r0, #1
 800302c:	e000      	b.n	8003030 <HAL_GPIO_ReadPin+0xe>
 800302e:	2000      	movs	r0, #0
 8003030:	4770      	bx	lr

08003032 <HAL_GPIO_TogglePin>:
 8003032:	b510      	push	{r4, lr}
 8003034:	68c2      	ldr	r2, [r0, #12]
 8003036:	ea21 0302 	bic.w	r3, r1, r2
 800303a:	ea02 0401 	and.w	r4, r2, r1
 800303e:	ea43 4304 	orr.w	r3, r3, r4, lsl #16
 8003042:	6103      	str	r3, [r0, #16]
 8003044:	bd10      	pop	{r4, pc}

08003046 <HAL_GPIO_WritePin>:
 8003046:	b10a      	cbz	r2, 800304c <HAL_GPIO_WritePin+0x6>
 8003048:	6101      	str	r1, [r0, #16]
 800304a:	e001      	b.n	8003050 <HAL_GPIO_WritePin+0xa>
 800304c:	040b      	lsls	r3, r1, #16
 800304e:	6103      	str	r3, [r0, #16]
 8003050:	4770      	bx	lr
	...

08003054 <HAL_GetDEVID>:
 8003054:	4802      	ldr	r0, [pc, #8]	@ (8003060 <HAL_GetDEVID+0xc>)
 8003056:	6800      	ldr	r0, [r0, #0]
 8003058:	f3c0 000b 	ubfx	r0, r0, #0, #12
 800305c:	4770      	bx	lr
 800305e:	0000      	.short	0x0000
 8003060:	e0042000 	.word	0xe0042000

08003064 <HAL_GetHalVersion>:
 8003064:	4800      	ldr	r0, [pc, #0]	@ (8003068 <HAL_GetHalVersion+0x4>)
 8003066:	4770      	bx	lr
 8003068:	01010a00 	.word	0x01010a00

0800306c <HAL_GetREVID>:
 800306c:	4801      	ldr	r0, [pc, #4]	@ (8003074 <HAL_GetREVID+0x8>)
 800306e:	6800      	ldr	r0, [r0, #0]
 8003070:	0c00      	lsrs	r0, r0, #16
 8003072:	4770      	bx	lr
 8003074:	e0042000 	.word	0xe0042000

08003078 <HAL_GetTick>:
 8003078:	4801      	ldr	r0, [pc, #4]	@ (8003080 <HAL_GetTick+0x8>)
 800307a:	6800      	ldr	r0, [r0, #0]
 800307c:	4770      	bx	lr
 800307e:	0000      	.short	0x0000
 8003080:	2000000c 	.word	0x2000000c

08003084 <HAL_GetTickFreq>:
 8003084:	4801      	ldr	r0, [pc, #4]	@ (800308c <HAL_GetTickFreq+0x8>)
 8003086:	7800      	ldrb	r0, [r0, #0]
 8003088:	4770      	bx	lr
 800308a:	0000      	.short	0x0000
 800308c:	20000014 	.word	0x20000014

08003090 <HAL_GetTickPrio>:
 8003090:	4801      	ldr	r0, [pc, #4]	@ (8003098 <HAL_GetTickPrio+0x8>)
 8003092:	6800      	ldr	r0, [r0, #0]
 8003094:	4770      	bx	lr
 8003096:	0000      	.short	0x0000
 8003098:	20000010 	.word	0x20000010

0800309c <HAL_GetUIDw0>:
 800309c:	4801      	ldr	r0, [pc, #4]	@ (80030a4 <HAL_GetUIDw0+0x8>)
 800309e:	6800      	ldr	r0, [r0, #0]
 80030a0:	4770      	bx	lr
 80030a2:	0000      	.short	0x0000
 80030a4:	1ffff7e8 	.word	0x1ffff7e8

080030a8 <HAL_GetUIDw1>:
 80030a8:	4801      	ldr	r0, [pc, #4]	@ (80030b0 <HAL_GetUIDw1+0x8>)
 80030aa:	6800      	ldr	r0, [r0, #0]
 80030ac:	4770      	bx	lr
 80030ae:	0000      	.short	0x0000
 80030b0:	1ffff7ec 	.word	0x1ffff7ec

080030b4 <HAL_GetUIDw2>:
 80030b4:	4801      	ldr	r0, [pc, #4]	@ (80030bc <HAL_GetUIDw2+0x8>)
 80030b6:	6800      	ldr	r0, [r0, #0]
 80030b8:	4770      	bx	lr
 80030ba:	0000      	.short	0x0000
 80030bc:	1ffff7f0 	.word	0x1ffff7f0

080030c0 <HAL_HalfDuplex_EnableReceiver>:
 80030c0:	4601      	mov	r1, r0
 80030c2:	2200      	movs	r2, #0
 80030c4:	bf00      	nop
 80030c6:	f891 0040 	ldrb.w	r0, [r1, #64]	@ 0x40
 80030ca:	2801      	cmp	r0, #1
 80030cc:	d101      	bne.n	80030d2 <HAL_HalfDuplex_EnableReceiver+0x12>
 80030ce:	2002      	movs	r0, #2
 80030d0:	4770      	bx	lr
 80030d2:	2001      	movs	r0, #1
 80030d4:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 80030d8:	bf00      	nop
 80030da:	2024      	movs	r0, #36	@ 0x24
 80030dc:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 80030e0:	6808      	ldr	r0, [r1, #0]
 80030e2:	68c2      	ldr	r2, [r0, #12]
 80030e4:	f022 020c 	bic.w	r2, r2, #12
 80030e8:	f042 0204 	orr.w	r2, r2, #4
 80030ec:	6808      	ldr	r0, [r1, #0]
 80030ee:	60c2      	str	r2, [r0, #12]
 80030f0:	2020      	movs	r0, #32
 80030f2:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 80030f6:	bf00      	nop
 80030f8:	2000      	movs	r0, #0
 80030fa:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 80030fe:	bf00      	nop
 8003100:	bf00      	nop
 8003102:	e7e5      	b.n	80030d0 <HAL_HalfDuplex_EnableReceiver+0x10>

08003104 <HAL_HalfDuplex_EnableTransmitter>:
 8003104:	4601      	mov	r1, r0
 8003106:	2200      	movs	r2, #0
 8003108:	bf00      	nop
 800310a:	f891 0040 	ldrb.w	r0, [r1, #64]	@ 0x40
 800310e:	2801      	cmp	r0, #1
 8003110:	d101      	bne.n	8003116 <HAL_HalfDuplex_EnableTransmitter+0x12>
 8003112:	2002      	movs	r0, #2
 8003114:	4770      	bx	lr
 8003116:	2001      	movs	r0, #1
 8003118:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 800311c:	bf00      	nop
 800311e:	2024      	movs	r0, #36	@ 0x24
 8003120:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 8003124:	6808      	ldr	r0, [r1, #0]
 8003126:	68c2      	ldr	r2, [r0, #12]
 8003128:	f022 020c 	bic.w	r2, r2, #12
 800312c:	f042 0208 	orr.w	r2, r2, #8
 8003130:	6808      	ldr	r0, [r1, #0]
 8003132:	60c2      	str	r2, [r0, #12]
 8003134:	2020      	movs	r0, #32
 8003136:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 800313a:	bf00      	nop
 800313c:	2000      	movs	r0, #0
 800313e:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 8003142:	bf00      	nop
 8003144:	bf00      	nop
 8003146:	e7e5      	b.n	8003114 <HAL_HalfDuplex_EnableTransmitter+0x10>

08003148 <HAL_HalfDuplex_Init>:
 8003148:	b510      	push	{r4, lr}
 800314a:	4604      	mov	r4, r0
 800314c:	b90c      	cbnz	r4, 8003152 <HAL_HalfDuplex_Init+0xa>
 800314e:	2001      	movs	r0, #1
 8003150:	bd10      	pop	{r4, pc}
 8003152:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 8003156:	b928      	cbnz	r0, 8003164 <HAL_HalfDuplex_Init+0x1c>
 8003158:	2000      	movs	r0, #0
 800315a:	f884 0040 	strb.w	r0, [r4, #64]	@ 0x40
 800315e:	4620      	mov	r0, r4
 8003160:	f002 f8f0 	bl	8005344 <HAL_UART_MspInit>
 8003164:	2024      	movs	r0, #36	@ 0x24
 8003166:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 800316a:	6820      	ldr	r0, [r4, #0]
 800316c:	68c0      	ldr	r0, [r0, #12]
 800316e:	f420 5000 	bic.w	r0, r0, #8192	@ 0x2000
 8003172:	6821      	ldr	r1, [r4, #0]
 8003174:	60c8      	str	r0, [r1, #12]
 8003176:	4620      	mov	r0, r4
 8003178:	f002 fd68 	bl	8005c4c <UART_SetConfig>
 800317c:	6820      	ldr	r0, [r4, #0]
 800317e:	6900      	ldr	r0, [r0, #16]
 8003180:	f420 4090 	bic.w	r0, r0, #18432	@ 0x4800
 8003184:	6821      	ldr	r1, [r4, #0]
 8003186:	6108      	str	r0, [r1, #16]
 8003188:	6820      	ldr	r0, [r4, #0]
 800318a:	6940      	ldr	r0, [r0, #20]
 800318c:	f020 0022 	bic.w	r0, r0, #34	@ 0x22
 8003190:	6821      	ldr	r1, [r4, #0]
 8003192:	6148      	str	r0, [r1, #20]
 8003194:	6820      	ldr	r0, [r4, #0]
 8003196:	6940      	ldr	r0, [r0, #20]
 8003198:	f040 0008 	orr.w	r0, r0, #8
 800319c:	6821      	ldr	r1, [r4, #0]
 800319e:	6148      	str	r0, [r1, #20]
 80031a0:	6820      	ldr	r0, [r4, #0]
 80031a2:	68c0      	ldr	r0, [r0, #12]
 80031a4:	f440 5000 	orr.w	r0, r0, #8192	@ 0x2000
 80031a8:	6821      	ldr	r1, [r4, #0]
 80031aa:	60c8      	str	r0, [r1, #12]
 80031ac:	2000      	movs	r0, #0
 80031ae:	6460      	str	r0, [r4, #68]	@ 0x44
 80031b0:	2020      	movs	r0, #32
 80031b2:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 80031b6:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 80031ba:	2000      	movs	r0, #0
 80031bc:	6360      	str	r0, [r4, #52]	@ 0x34
 80031be:	bf00      	nop
 80031c0:	e7c6      	b.n	8003150 <HAL_HalfDuplex_Init+0x8>
	...

080031c4 <HAL_IncTick>:
 80031c4:	4803      	ldr	r0, [pc, #12]	@ (80031d4 <HAL_IncTick+0x10>)
 80031c6:	6800      	ldr	r0, [r0, #0]
 80031c8:	4903      	ldr	r1, [pc, #12]	@ (80031d8 <HAL_IncTick+0x14>)
 80031ca:	7809      	ldrb	r1, [r1, #0]
 80031cc:	4408      	add	r0, r1
 80031ce:	4901      	ldr	r1, [pc, #4]	@ (80031d4 <HAL_IncTick+0x10>)
 80031d0:	6008      	str	r0, [r1, #0]
 80031d2:	4770      	bx	lr
 80031d4:	2000000c 	.word	0x2000000c
 80031d8:	20000014 	.word	0x20000014

080031dc <HAL_Init>:
 80031dc:	b510      	push	{r4, lr}
 80031de:	4808      	ldr	r0, [pc, #32]	@ (8003200 <HAL_Init+0x24>)
 80031e0:	6800      	ldr	r0, [r0, #0]
 80031e2:	f040 0010 	orr.w	r0, r0, #16
 80031e6:	4906      	ldr	r1, [pc, #24]	@ (8003200 <HAL_Init+0x24>)
 80031e8:	6008      	str	r0, [r1, #0]
 80031ea:	2003      	movs	r0, #3
 80031ec:	f000 fa80 	bl	80036f0 <HAL_NVIC_SetPriorityGrouping>
 80031f0:	200f      	movs	r0, #15
 80031f2:	f000 f807 	bl	8003204 <HAL_InitTick>
 80031f6:	f000 f89d 	bl	8003334 <HAL_MspInit>
 80031fa:	2000      	movs	r0, #0
 80031fc:	bd10      	pop	{r4, pc}
 80031fe:	0000      	.short	0x0000
 8003200:	40022000 	.word	0x40022000

08003204 <HAL_InitTick>:
 8003204:	b570      	push	{r4, r5, r6, lr}
 8003206:	4604      	mov	r4, r0
 8003208:	480e      	ldr	r0, [pc, #56]	@ (8003244 <HAL_InitTick+0x40>)
 800320a:	7800      	ldrb	r0, [r0, #0]
 800320c:	f44f 717a 	mov.w	r1, #1000	@ 0x3e8
 8003210:	fbb1 f0f0 	udiv	r0, r1, r0
 8003214:	490c      	ldr	r1, [pc, #48]	@ (8003248 <HAL_InitTick+0x44>)
 8003216:	6809      	ldr	r1, [r1, #0]
 8003218:	fbb1 f5f0 	udiv	r5, r1, r0
 800321c:	4628      	mov	r0, r5
 800321e:	f001 f9e1 	bl	80045e4 <HAL_SYSTICK_Config>
 8003222:	b108      	cbz	r0, 8003228 <HAL_InitTick+0x24>
 8003224:	2001      	movs	r0, #1
 8003226:	bd70      	pop	{r4, r5, r6, pc}
 8003228:	2c10      	cmp	r4, #16
 800322a:	d207      	bcs.n	800323c <HAL_InitTick+0x38>
 800322c:	2200      	movs	r2, #0
 800322e:	4621      	mov	r1, r4
 8003230:	1e50      	subs	r0, r2, #1
 8003232:	f000 fa1f 	bl	8003674 <HAL_NVIC_SetPriority>
 8003236:	4805      	ldr	r0, [pc, #20]	@ (800324c <HAL_InitTick+0x48>)
 8003238:	6004      	str	r4, [r0, #0]
 800323a:	e001      	b.n	8003240 <HAL_InitTick+0x3c>
 800323c:	2001      	movs	r0, #1
 800323e:	e7f2      	b.n	8003226 <HAL_InitTick+0x22>
 8003240:	2000      	movs	r0, #0
 8003242:	e7f0      	b.n	8003226 <HAL_InitTick+0x22>
 8003244:	20000014 	.word	0x20000014
 8003248:	20000018 	.word	0x20000018
 800324c:	20000010 	.word	0x20000010

08003250 <HAL_LIN_Init>:
 8003250:	b570      	push	{r4, r5, r6, lr}
 8003252:	4604      	mov	r4, r0
 8003254:	460d      	mov	r5, r1
 8003256:	b90c      	cbnz	r4, 800325c <HAL_LIN_Init+0xc>
 8003258:	2001      	movs	r0, #1
 800325a:	bd70      	pop	{r4, r5, r6, pc}
 800325c:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 8003260:	b928      	cbnz	r0, 800326e <HAL_LIN_Init+0x1e>
 8003262:	2000      	movs	r0, #0
 8003264:	f884 0040 	strb.w	r0, [r4, #64]	@ 0x40
 8003268:	4620      	mov	r0, r4
 800326a:	f002 f86b 	bl	8005344 <HAL_UART_MspInit>
 800326e:	2024      	movs	r0, #36	@ 0x24
 8003270:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8003274:	6820      	ldr	r0, [r4, #0]
 8003276:	68c0      	ldr	r0, [r0, #12]
 8003278:	f420 5000 	bic.w	r0, r0, #8192	@ 0x2000
 800327c:	6821      	ldr	r1, [r4, #0]
 800327e:	60c8      	str	r0, [r1, #12]
 8003280:	4620      	mov	r0, r4
 8003282:	f002 fce3 	bl	8005c4c <UART_SetConfig>
 8003286:	6820      	ldr	r0, [r4, #0]
 8003288:	6900      	ldr	r0, [r0, #16]
 800328a:	f420 6000 	bic.w	r0, r0, #2048	@ 0x800
 800328e:	6821      	ldr	r1, [r4, #0]
 8003290:	6108      	str	r0, [r1, #16]
 8003292:	6820      	ldr	r0, [r4, #0]
 8003294:	6940      	ldr	r0, [r0, #20]
 8003296:	f020 002a 	bic.w	r0, r0, #42	@ 0x2a
 800329a:	6821      	ldr	r1, [r4, #0]
 800329c:	6148      	str	r0, [r1, #20]
 800329e:	6820      	ldr	r0, [r4, #0]
 80032a0:	6900      	ldr	r0, [r0, #16]
 80032a2:	f440 4080 	orr.w	r0, r0, #16384	@ 0x4000
 80032a6:	6821      	ldr	r1, [r4, #0]
 80032a8:	6108      	str	r0, [r1, #16]
 80032aa:	6820      	ldr	r0, [r4, #0]
 80032ac:	6900      	ldr	r0, [r0, #16]
 80032ae:	f020 0020 	bic.w	r0, r0, #32
 80032b2:	6821      	ldr	r1, [r4, #0]
 80032b4:	6108      	str	r0, [r1, #16]
 80032b6:	6820      	ldr	r0, [r4, #0]
 80032b8:	6900      	ldr	r0, [r0, #16]
 80032ba:	4328      	orrs	r0, r5
 80032bc:	6821      	ldr	r1, [r4, #0]
 80032be:	6108      	str	r0, [r1, #16]
 80032c0:	6820      	ldr	r0, [r4, #0]
 80032c2:	68c0      	ldr	r0, [r0, #12]
 80032c4:	f440 5000 	orr.w	r0, r0, #8192	@ 0x2000
 80032c8:	6821      	ldr	r1, [r4, #0]
 80032ca:	60c8      	str	r0, [r1, #12]
 80032cc:	2000      	movs	r0, #0
 80032ce:	6460      	str	r0, [r4, #68]	@ 0x44
 80032d0:	2020      	movs	r0, #32
 80032d2:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 80032d6:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 80032da:	2000      	movs	r0, #0
 80032dc:	6360      	str	r0, [r4, #52]	@ 0x34
 80032de:	bf00      	nop
 80032e0:	e7bb      	b.n	800325a <HAL_LIN_Init+0xa>

080032e2 <HAL_LIN_SendBreak>:
 80032e2:	4601      	mov	r1, r0
 80032e4:	bf00      	nop
 80032e6:	f891 0040 	ldrb.w	r0, [r1, #64]	@ 0x40
 80032ea:	2801      	cmp	r0, #1
 80032ec:	d101      	bne.n	80032f2 <HAL_LIN_SendBreak+0x10>
 80032ee:	2002      	movs	r0, #2
 80032f0:	4770      	bx	lr
 80032f2:	2001      	movs	r0, #1
 80032f4:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 80032f8:	bf00      	nop
 80032fa:	2024      	movs	r0, #36	@ 0x24
 80032fc:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 8003300:	bf00      	nop
 8003302:	bf00      	nop
 8003304:	680a      	ldr	r2, [r1, #0]
 8003306:	320c      	adds	r2, #12
 8003308:	e852 2f00 	ldrex	r2, [r2]
 800330c:	f042 0001 	orr.w	r0, r2, #1
 8003310:	680a      	ldr	r2, [r1, #0]
 8003312:	320c      	adds	r2, #12
 8003314:	e842 0300 	strex	r3, r0, [r2]
 8003318:	2b00      	cmp	r3, #0
 800331a:	d1f3      	bne.n	8003304 <HAL_LIN_SendBreak+0x22>
 800331c:	bf00      	nop
 800331e:	2020      	movs	r0, #32
 8003320:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 8003324:	bf00      	nop
 8003326:	2000      	movs	r0, #0
 8003328:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 800332c:	bf00      	nop
 800332e:	bf00      	nop
 8003330:	e7de      	b.n	80032f0 <HAL_LIN_SendBreak+0xe>

08003332 <HAL_MspDeInit>:
 8003332:	4770      	bx	lr

08003334 <HAL_MspInit>:
 8003334:	b508      	push	{r3, lr}
 8003336:	bf00      	nop
 8003338:	4811      	ldr	r0, [pc, #68]	@ (8003380 <HAL_MspInit+0x4c>)
 800333a:	6980      	ldr	r0, [r0, #24]
 800333c:	f040 0001 	orr.w	r0, r0, #1
 8003340:	490f      	ldr	r1, [pc, #60]	@ (8003380 <HAL_MspInit+0x4c>)
 8003342:	6188      	str	r0, [r1, #24]
 8003344:	4608      	mov	r0, r1
 8003346:	6980      	ldr	r0, [r0, #24]
 8003348:	f000 0001 	and.w	r0, r0, #1
 800334c:	9000      	str	r0, [sp, #0]
 800334e:	bf00      	nop
 8003350:	bf00      	nop
 8003352:	bf00      	nop
 8003354:	4608      	mov	r0, r1
 8003356:	69c0      	ldr	r0, [r0, #28]
 8003358:	f040 5080 	orr.w	r0, r0, #268435456	@ 0x10000000
 800335c:	61c8      	str	r0, [r1, #28]
 800335e:	4608      	mov	r0, r1
 8003360:	69c0      	ldr	r0, [r0, #28]
 8003362:	f000 5080 	and.w	r0, r0, #268435456	@ 0x10000000
 8003366:	9000      	str	r0, [sp, #0]
 8003368:	bf00      	nop
 800336a:	bf00      	nop
 800336c:	bf00      	nop
 800336e:	4905      	ldr	r1, [pc, #20]	@ (8003384 <HAL_MspInit+0x50>)
 8003370:	6848      	ldr	r0, [r1, #4]
 8003372:	f020 60e0 	bic.w	r0, r0, #117440512	@ 0x7000000
 8003376:	f040 7000 	orr.w	r0, r0, #33554432	@ 0x2000000
 800337a:	6048      	str	r0, [r1, #4]
 800337c:	bf00      	nop
 800337e:	bd08      	pop	{r3, pc}
 8003380:	40021000 	.word	0x40021000
 8003384:	40010000 	.word	0x40010000
 8003388:	4770      	bx	lr

0800338a <HAL_MultiProcessor_EnterMuteMode>:
 800338a:	4601      	mov	r1, r0
 800338c:	bf00      	nop
 800338e:	f891 0040 	ldrb.w	r0, [r1, #64]	@ 0x40
 8003392:	2801      	cmp	r0, #1
 8003394:	d101      	bne.n	800339a <HAL_MultiProcessor_EnterMuteMode+0x10>
 8003396:	2002      	movs	r0, #2
 8003398:	4770      	bx	lr
 800339a:	2001      	movs	r0, #1
 800339c:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 80033a0:	bf00      	nop
 80033a2:	2024      	movs	r0, #36	@ 0x24
 80033a4:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 80033a8:	bf00      	nop
 80033aa:	bf00      	nop
 80033ac:	680a      	ldr	r2, [r1, #0]
 80033ae:	320c      	adds	r2, #12
 80033b0:	e852 2f00 	ldrex	r2, [r2]
 80033b4:	f042 0002 	orr.w	r0, r2, #2
 80033b8:	680a      	ldr	r2, [r1, #0]
 80033ba:	320c      	adds	r2, #12
 80033bc:	e842 0300 	strex	r3, r0, [r2]
 80033c0:	2b00      	cmp	r3, #0
 80033c2:	d1f3      	bne.n	80033ac <HAL_MultiProcessor_EnterMuteMode+0x22>
 80033c4:	bf00      	nop
 80033c6:	2020      	movs	r0, #32
 80033c8:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 80033cc:	2000      	movs	r0, #0
 80033ce:	6348      	str	r0, [r1, #52]	@ 0x34
 80033d0:	bf00      	nop
 80033d2:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 80033d6:	bf00      	nop
 80033d8:	bf00      	nop
 80033da:	e7dd      	b.n	8003398 <HAL_MultiProcessor_EnterMuteMode+0xe>

080033dc <HAL_MultiProcessor_ExitMuteMode>:
 80033dc:	4601      	mov	r1, r0
 80033de:	bf00      	nop
 80033e0:	f891 0040 	ldrb.w	r0, [r1, #64]	@ 0x40
 80033e4:	2801      	cmp	r0, #1
 80033e6:	d101      	bne.n	80033ec <HAL_MultiProcessor_ExitMuteMode+0x10>
 80033e8:	2002      	movs	r0, #2
 80033ea:	4770      	bx	lr
 80033ec:	2001      	movs	r0, #1
 80033ee:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 80033f2:	bf00      	nop
 80033f4:	2024      	movs	r0, #36	@ 0x24
 80033f6:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 80033fa:	bf00      	nop
 80033fc:	bf00      	nop
 80033fe:	680a      	ldr	r2, [r1, #0]
 8003400:	320c      	adds	r2, #12
 8003402:	e852 2f00 	ldrex	r2, [r2]
 8003406:	f022 0002 	bic.w	r0, r2, #2
 800340a:	680a      	ldr	r2, [r1, #0]
 800340c:	320c      	adds	r2, #12
 800340e:	e842 0300 	strex	r3, r0, [r2]
 8003412:	2b00      	cmp	r3, #0
 8003414:	d1f3      	bne.n	80033fe <HAL_MultiProcessor_ExitMuteMode+0x22>
 8003416:	bf00      	nop
 8003418:	2020      	movs	r0, #32
 800341a:	f881 0041 	strb.w	r0, [r1, #65]	@ 0x41
 800341e:	2000      	movs	r0, #0
 8003420:	6348      	str	r0, [r1, #52]	@ 0x34
 8003422:	bf00      	nop
 8003424:	f881 0040 	strb.w	r0, [r1, #64]	@ 0x40
 8003428:	bf00      	nop
 800342a:	bf00      	nop
 800342c:	e7dd      	b.n	80033ea <HAL_MultiProcessor_ExitMuteMode+0xe>

0800342e <HAL_MultiProcessor_Init>:
 800342e:	b570      	push	{r4, r5, r6, lr}
 8003430:	4604      	mov	r4, r0
 8003432:	460d      	mov	r5, r1
 8003434:	4616      	mov	r6, r2
 8003436:	b90c      	cbnz	r4, 800343c <HAL_MultiProcessor_Init+0xe>
 8003438:	2001      	movs	r0, #1
 800343a:	bd70      	pop	{r4, r5, r6, pc}
 800343c:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 8003440:	b928      	cbnz	r0, 800344e <HAL_MultiProcessor_Init+0x20>
 8003442:	2000      	movs	r0, #0
 8003444:	f884 0040 	strb.w	r0, [r4, #64]	@ 0x40
 8003448:	4620      	mov	r0, r4
 800344a:	f001 ff7b 	bl	8005344 <HAL_UART_MspInit>
 800344e:	2024      	movs	r0, #36	@ 0x24
 8003450:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8003454:	6820      	ldr	r0, [r4, #0]
 8003456:	68c0      	ldr	r0, [r0, #12]
 8003458:	f420 5000 	bic.w	r0, r0, #8192	@ 0x2000
 800345c:	6821      	ldr	r1, [r4, #0]
 800345e:	60c8      	str	r0, [r1, #12]
 8003460:	4620      	mov	r0, r4
 8003462:	f002 fbf3 	bl	8005c4c <UART_SetConfig>
 8003466:	6820      	ldr	r0, [r4, #0]
 8003468:	6900      	ldr	r0, [r0, #16]
 800346a:	f420 4090 	bic.w	r0, r0, #18432	@ 0x4800
 800346e:	6821      	ldr	r1, [r4, #0]
 8003470:	6108      	str	r0, [r1, #16]
 8003472:	6820      	ldr	r0, [r4, #0]
 8003474:	6940      	ldr	r0, [r0, #20]
 8003476:	f020 002a 	bic.w	r0, r0, #42	@ 0x2a
 800347a:	6821      	ldr	r1, [r4, #0]
 800347c:	6148      	str	r0, [r1, #20]
 800347e:	6820      	ldr	r0, [r4, #0]
 8003480:	6900      	ldr	r0, [r0, #16]
 8003482:	f020 000f 	bic.w	r0, r0, #15
 8003486:	6821      	ldr	r1, [r4, #0]
 8003488:	6108      	str	r0, [r1, #16]
 800348a:	6820      	ldr	r0, [r4, #0]
 800348c:	6900      	ldr	r0, [r0, #16]
 800348e:	4328      	orrs	r0, r5
 8003490:	6821      	ldr	r1, [r4, #0]
 8003492:	6108      	str	r0, [r1, #16]
 8003494:	6820      	ldr	r0, [r4, #0]
 8003496:	68c0      	ldr	r0, [r0, #12]
 8003498:	f420 6000 	bic.w	r0, r0, #2048	@ 0x800
 800349c:	6821      	ldr	r1, [r4, #0]
 800349e:	60c8      	str	r0, [r1, #12]
 80034a0:	6820      	ldr	r0, [r4, #0]
 80034a2:	68c0      	ldr	r0, [r0, #12]
 80034a4:	4330      	orrs	r0, r6
 80034a6:	6821      	ldr	r1, [r4, #0]
 80034a8:	60c8      	str	r0, [r1, #12]
 80034aa:	6820      	ldr	r0, [r4, #0]
 80034ac:	68c0      	ldr	r0, [r0, #12]
 80034ae:	f440 5000 	orr.w	r0, r0, #8192	@ 0x2000
 80034b2:	6821      	ldr	r1, [r4, #0]
 80034b4:	60c8      	str	r0, [r1, #12]
 80034b6:	2000      	movs	r0, #0
 80034b8:	6460      	str	r0, [r4, #68]	@ 0x44
 80034ba:	2020      	movs	r0, #32
 80034bc:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 80034c0:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 80034c4:	2000      	movs	r0, #0
 80034c6:	6360      	str	r0, [r4, #52]	@ 0x34
 80034c8:	bf00      	nop
 80034ca:	e7b6      	b.n	800343a <HAL_MultiProcessor_Init+0xc>

080034cc <HAL_NVIC_ClearPendingIRQ>:
 80034cc:	b510      	push	{r4, lr}
 80034ce:	4601      	mov	r1, r0
 80034d0:	4608      	mov	r0, r1
 80034d2:	2800      	cmp	r0, #0
 80034d4:	db07      	blt.n	80034e6 <HAL_NVIC_ClearPendingIRQ+0x1a>
 80034d6:	f000 031f 	and.w	r3, r0, #31
 80034da:	2201      	movs	r2, #1
 80034dc:	409a      	lsls	r2, r3
 80034de:	4b03      	ldr	r3, [pc, #12]	@ (80034ec <HAL_NVIC_ClearPendingIRQ+0x20>)
 80034e0:	0944      	lsrs	r4, r0, #5
 80034e2:	f843 2024 	str.w	r2, [r3, r4, lsl #2]
 80034e6:	bf00      	nop
 80034e8:	bd10      	pop	{r4, pc}
 80034ea:	0000      	.short	0x0000
 80034ec:	e000e280 	.word	0xe000e280

080034f0 <HAL_NVIC_DisableIRQ>:
 80034f0:	b510      	push	{r4, lr}
 80034f2:	4601      	mov	r1, r0
 80034f4:	4608      	mov	r0, r1
 80034f6:	2800      	cmp	r0, #0
 80034f8:	db17      	blt.n	800352a <HAL_NVIC_DisableIRQ+0x3a>
 80034fa:	f000 031f 	and.w	r3, r0, #31
 80034fe:	2201      	movs	r2, #1
 8003500:	409a      	lsls	r2, r3
 8003502:	4b0b      	ldr	r3, [pc, #44]	@ (8003530 <HAL_NVIC_DisableIRQ+0x40>)
 8003504:	0944      	lsrs	r4, r0, #5
 8003506:	f843 2024 	str.w	r2, [r3, r4, lsl #2]
 800350a:	bf00      	nop
 800350c:	bf00      	nop
 800350e:	bf00      	nop
 8003510:	f3bf 8f4f 	dsb	sy
 8003514:	bf00      	nop
 8003516:	bf00      	nop
 8003518:	bf00      	nop
 800351a:	bf00      	nop
 800351c:	bf00      	nop
 800351e:	bf00      	nop
 8003520:	f3bf 8f6f 	isb	sy
 8003524:	bf00      	nop
 8003526:	bf00      	nop
 8003528:	bf00      	nop
 800352a:	bf00      	nop
 800352c:	bd10      	pop	{r4, pc}
 800352e:	0000      	.short	0x0000
 8003530:	e000e180 	.word	0xe000e180

08003534 <HAL_NVIC_EnableIRQ>:
 8003534:	4601      	mov	r1, r0
 8003536:	4608      	mov	r0, r1
 8003538:	2800      	cmp	r0, #0
 800353a:	db09      	blt.n	8003550 <HAL_NVIC_EnableIRQ+0x1c>
 800353c:	f000 031f 	and.w	r3, r0, #31
 8003540:	2201      	movs	r2, #1
 8003542:	409a      	lsls	r2, r3
 8003544:	0943      	lsrs	r3, r0, #5
 8003546:	009b      	lsls	r3, r3, #2
 8003548:	f103 23e0 	add.w	r3, r3, #3758153728	@ 0xe000e000
 800354c:	f8c3 2100 	str.w	r2, [r3, #256]	@ 0x100
 8003550:	bf00      	nop
 8003552:	4770      	bx	lr

08003554 <HAL_NVIC_GetActive>:
 8003554:	b510      	push	{r4, lr}
 8003556:	4601      	mov	r1, r0
 8003558:	4608      	mov	r0, r1
 800355a:	2800      	cmp	r0, #0
 800355c:	db0d      	blt.n	800357a <HAL_NVIC_GetActive+0x26>
 800355e:	4a08      	ldr	r2, [pc, #32]	@ (8003580 <HAL_NVIC_GetActive+0x2c>)
 8003560:	0943      	lsrs	r3, r0, #5
 8003562:	f852 2023 	ldr.w	r2, [r2, r3, lsl #2]
 8003566:	f000 041f 	and.w	r4, r0, #31
 800356a:	2301      	movs	r3, #1
 800356c:	40a3      	lsls	r3, r4
 800356e:	401a      	ands	r2, r3
 8003570:	b10a      	cbz	r2, 8003576 <HAL_NVIC_GetActive+0x22>
 8003572:	2201      	movs	r2, #1
 8003574:	e002      	b.n	800357c <HAL_NVIC_GetActive+0x28>
 8003576:	2200      	movs	r2, #0
 8003578:	e000      	b.n	800357c <HAL_NVIC_GetActive+0x28>
 800357a:	2200      	movs	r2, #0
 800357c:	4610      	mov	r0, r2
 800357e:	bd10      	pop	{r4, pc}
 8003580:	e000e300 	.word	0xe000e300

08003584 <HAL_NVIC_GetPendingIRQ>:
 8003584:	b510      	push	{r4, lr}
 8003586:	4601      	mov	r1, r0
 8003588:	4608      	mov	r0, r1
 800358a:	2800      	cmp	r0, #0
 800358c:	db0d      	blt.n	80035aa <HAL_NVIC_GetPendingIRQ+0x26>
 800358e:	4a08      	ldr	r2, [pc, #32]	@ (80035b0 <HAL_NVIC_GetPendingIRQ+0x2c>)
 8003590:	0943      	lsrs	r3, r0, #5
 8003592:	f852 2023 	ldr.w	r2, [r2, r3, lsl #2]
 8003596:	f000 041f 	and.w	r4, r0, #31
 800359a:	2301      	movs	r3, #1
 800359c:	40a3      	lsls	r3, r4
 800359e:	401a      	ands	r2, r3
 80035a0:	b10a      	cbz	r2, 80035a6 <HAL_NVIC_GetPendingIRQ+0x22>
 80035a2:	2201      	movs	r2, #1
 80035a4:	e002      	b.n	80035ac <HAL_NVIC_GetPendingIRQ+0x28>
 80035a6:	2200      	movs	r2, #0
 80035a8:	e000      	b.n	80035ac <HAL_NVIC_GetPendingIRQ+0x28>
 80035aa:	2200      	movs	r2, #0
 80035ac:	4610      	mov	r0, r2
 80035ae:	bd10      	pop	{r4, pc}
 80035b0:	e000e200 	.word	0xe000e200

080035b4 <HAL_NVIC_GetPriority>:
 80035b4:	e92d 43f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, lr}
 80035b8:	4604      	mov	r4, r0
 80035ba:	4620      	mov	r0, r4
 80035bc:	2800      	cmp	r0, #0
 80035be:	db03      	blt.n	80035c8 <HAL_NVIC_GetPriority+0x14>
 80035c0:	4f1f      	ldr	r7, [pc, #124]	@ (8003640 <HAL_NVIC_GetPriority+0x8c>)
 80035c2:	5c3f      	ldrb	r7, [r7, r0]
 80035c4:	093f      	lsrs	r7, r7, #4
 80035c6:	e007      	b.n	80035d8 <HAL_NVIC_GetPriority+0x24>
 80035c8:	4f1e      	ldr	r7, [pc, #120]	@ (8003644 <HAL_NVIC_GetPriority+0x90>)
 80035ca:	f000 0c0f 	and.w	ip, r0, #15
 80035ce:	f1ac 0c04 	sub.w	ip, ip, #4
 80035d2:	f817 700c 	ldrb.w	r7, [r7, ip]
 80035d6:	093f      	lsrs	r7, r7, #4
 80035d8:	463d      	mov	r5, r7
 80035da:	460e      	mov	r6, r1
 80035dc:	f006 0007 	and.w	r0, r6, #7
 80035e0:	f1c0 0807 	rsb	r8, r0, #7
 80035e4:	f1b8 0f04 	cmp.w	r8, #4
 80035e8:	d902      	bls.n	80035f0 <HAL_NVIC_GetPriority+0x3c>
 80035ea:	f04f 0804 	mov.w	r8, #4
 80035ee:	e001      	b.n	80035f4 <HAL_NVIC_GetPriority+0x40>
 80035f0:	f1c0 0807 	rsb	r8, r0, #7
 80035f4:	46c4      	mov	ip, r8
 80035f6:	f100 0804 	add.w	r8, r0, #4
 80035fa:	f1b8 0f07 	cmp.w	r8, #7
 80035fe:	d202      	bcs.n	8003606 <HAL_NVIC_GetPriority+0x52>
 8003600:	f04f 0800 	mov.w	r8, #0
 8003604:	e001      	b.n	800360a <HAL_NVIC_GetPriority+0x56>
 8003606:	f1a0 0803 	sub.w	r8, r0, #3
 800360a:	4647      	mov	r7, r8
 800360c:	fa25 f807 	lsr.w	r8, r5, r7
 8003610:	f04f 0901 	mov.w	r9, #1
 8003614:	fa09 f90c 	lsl.w	r9, r9, ip
 8003618:	f1a9 0901 	sub.w	r9, r9, #1
 800361c:	ea08 0809 	and.w	r8, r8, r9
 8003620:	f8c2 8000 	str.w	r8, [r2]
 8003624:	f04f 0801 	mov.w	r8, #1
 8003628:	fa08 f807 	lsl.w	r8, r8, r7
 800362c:	f1a8 0801 	sub.w	r8, r8, #1
 8003630:	ea08 0805 	and.w	r8, r8, r5
 8003634:	f8c3 8000 	str.w	r8, [r3]
 8003638:	bf00      	nop
 800363a:	e8bd 83f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, pc}
 800363e:	0000      	.short	0x0000
 8003640:	e000e400 	.word	0xe000e400
 8003644:	e000ed18 	.word	0xe000ed18

08003648 <HAL_NVIC_GetPriorityGrouping>:
 8003648:	b510      	push	{r4, lr}
 800364a:	f002 fc89 	bl	8005f60 <__NVIC_GetPriorityGrouping>
 800364e:	bd10      	pop	{r4, pc}

08003650 <HAL_NVIC_SetPendingIRQ>:
 8003650:	b510      	push	{r4, lr}
 8003652:	4601      	mov	r1, r0
 8003654:	4608      	mov	r0, r1
 8003656:	2800      	cmp	r0, #0
 8003658:	db07      	blt.n	800366a <HAL_NVIC_SetPendingIRQ+0x1a>
 800365a:	f000 031f 	and.w	r3, r0, #31
 800365e:	2201      	movs	r2, #1
 8003660:	409a      	lsls	r2, r3
 8003662:	4b03      	ldr	r3, [pc, #12]	@ (8003670 <HAL_NVIC_SetPendingIRQ+0x20>)
 8003664:	0944      	lsrs	r4, r0, #5
 8003666:	f843 2024 	str.w	r2, [r3, r4, lsl #2]
 800366a:	bf00      	nop
 800366c:	bd10      	pop	{r4, pc}
 800366e:	0000      	.short	0x0000
 8003670:	e000e200 	.word	0xe000e200

08003674 <HAL_NVIC_SetPriority>:
 8003674:	e92d 5ff0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, ip, lr}
 8003678:	4680      	mov	r8, r0
 800367a:	460d      	mov	r5, r1
 800367c:	4616      	mov	r6, r2
 800367e:	2700      	movs	r7, #0
 8003680:	f002 fc6e 	bl	8005f60 <__NVIC_GetPriorityGrouping>
 8003684:	4607      	mov	r7, r0
 8003686:	4639      	mov	r1, r7
 8003688:	462a      	mov	r2, r5
 800368a:	4633      	mov	r3, r6
 800368c:	f001 0007 	and.w	r0, r1, #7
 8003690:	f1c0 0a07 	rsb	sl, r0, #7
 8003694:	f1ba 0f04 	cmp.w	sl, #4
 8003698:	d902      	bls.n	80036a0 <HAL_NVIC_SetPriority+0x2c>
 800369a:	f04f 0a04 	mov.w	sl, #4
 800369e:	e001      	b.n	80036a4 <HAL_NVIC_SetPriority+0x30>
 80036a0:	f1c0 0a07 	rsb	sl, r0, #7
 80036a4:	46d1      	mov	r9, sl
 80036a6:	f100 0a04 	add.w	sl, r0, #4
 80036aa:	f1ba 0f07 	cmp.w	sl, #7
 80036ae:	d202      	bcs.n	80036b6 <HAL_NVIC_SetPriority+0x42>
 80036b0:	f04f 0a00 	mov.w	sl, #0
 80036b4:	e001      	b.n	80036ba <HAL_NVIC_SetPriority+0x46>
 80036b6:	f1a0 0a03 	sub.w	sl, r0, #3
 80036ba:	46d4      	mov	ip, sl
 80036bc:	f04f 0a01 	mov.w	sl, #1
 80036c0:	fa0a fa09 	lsl.w	sl, sl, r9
 80036c4:	f1aa 0a01 	sub.w	sl, sl, #1
 80036c8:	ea0a 0a02 	and.w	sl, sl, r2
 80036cc:	fa0a fa0c 	lsl.w	sl, sl, ip
 80036d0:	f04f 0b01 	mov.w	fp, #1
 80036d4:	fa0b fb0c 	lsl.w	fp, fp, ip
 80036d8:	f1ab 0b01 	sub.w	fp, fp, #1
 80036dc:	ea0b 0b03 	and.w	fp, fp, r3
 80036e0:	ea4a 040b 	orr.w	r4, sl, fp
 80036e4:	4621      	mov	r1, r4
 80036e6:	4640      	mov	r0, r8
 80036e8:	f002 fc42 	bl	8005f70 <__NVIC_SetPriority>
 80036ec:	e8bd 9ff0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, ip, pc}

080036f0 <HAL_NVIC_SetPriorityGrouping>:
 80036f0:	bf00      	nop
 80036f2:	f000 0207 	and.w	r2, r0, #7
 80036f6:	4b06      	ldr	r3, [pc, #24]	@ (8003710 <HAL_NVIC_SetPriorityGrouping+0x20>)
 80036f8:	6819      	ldr	r1, [r3, #0]
 80036fa:	f64f 03ff 	movw	r3, #63743	@ 0xf8ff
 80036fe:	4019      	ands	r1, r3
 8003700:	4b04      	ldr	r3, [pc, #16]	@ (8003714 <HAL_NVIC_SetPriorityGrouping+0x24>)
 8003702:	430b      	orrs	r3, r1
 8003704:	ea43 2102 	orr.w	r1, r3, r2, lsl #8
 8003708:	4b01      	ldr	r3, [pc, #4]	@ (8003710 <HAL_NVIC_SetPriorityGrouping+0x20>)
 800370a:	6019      	str	r1, [r3, #0]
 800370c:	bf00      	nop
 800370e:	4770      	bx	lr
 8003710:	e000ed0c 	.word	0xe000ed0c
 8003714:	05fa0000 	.word	0x05fa0000

08003718 <HAL_NVIC_SystemReset>:
 8003718:	bf00      	nop
 800371a:	bf00      	nop
 800371c:	bf00      	nop
 800371e:	bf00      	nop
 8003720:	bf00      	nop
 8003722:	f3bf 8f4f 	dsb	sy
 8003726:	bf00      	nop
 8003728:	bf00      	nop
 800372a:	bf00      	nop
 800372c:	4809      	ldr	r0, [pc, #36]	@ (8003754 <HAL_NVIC_SystemReset+0x3c>)
 800372e:	6800      	ldr	r0, [r0, #0]
 8003730:	f400 60e0 	and.w	r0, r0, #1792	@ 0x700
 8003734:	4908      	ldr	r1, [pc, #32]	@ (8003758 <HAL_NVIC_SystemReset+0x40>)
 8003736:	4308      	orrs	r0, r1
 8003738:	1d00      	adds	r0, r0, #4
 800373a:	4906      	ldr	r1, [pc, #24]	@ (8003754 <HAL_NVIC_SystemReset+0x3c>)
 800373c:	6008      	str	r0, [r1, #0]
 800373e:	bf00      	nop
 8003740:	bf00      	nop
 8003742:	bf00      	nop
 8003744:	f3bf 8f4f 	dsb	sy
 8003748:	bf00      	nop
 800374a:	bf00      	nop
 800374c:	bf00      	nop
 800374e:	bf00      	nop
 8003750:	bf00      	nop
 8003752:	e7fd      	b.n	8003750 <HAL_NVIC_SystemReset+0x38>
 8003754:	e000ed0c 	.word	0xe000ed0c
 8003758:	05fa0000 	.word	0x05fa0000

0800375c <HAL_PWR_ConfigPVD>:
 800375c:	492a      	ldr	r1, [pc, #168]	@ (8003808 <HAL_PWR_ConfigPVD+0xac>)
 800375e:	6809      	ldr	r1, [r1, #0]
 8003760:	f021 01e0 	bic.w	r1, r1, #224	@ 0xe0
 8003764:	6802      	ldr	r2, [r0, #0]
 8003766:	4311      	orrs	r1, r2
 8003768:	4a27      	ldr	r2, [pc, #156]	@ (8003808 <HAL_PWR_ConfigPVD+0xac>)
 800376a:	6011      	str	r1, [r2, #0]
 800376c:	4927      	ldr	r1, [pc, #156]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 800376e:	6809      	ldr	r1, [r1, #0]
 8003770:	f421 3180 	bic.w	r1, r1, #65536	@ 0x10000
 8003774:	4a25      	ldr	r2, [pc, #148]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 8003776:	6011      	str	r1, [r2, #0]
 8003778:	1f11      	subs	r1, r2, #4
 800377a:	6809      	ldr	r1, [r1, #0]
 800377c:	f421 3180 	bic.w	r1, r1, #65536	@ 0x10000
 8003780:	1f12      	subs	r2, r2, #4
 8003782:	6011      	str	r1, [r2, #0]
 8003784:	4921      	ldr	r1, [pc, #132]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 8003786:	3108      	adds	r1, #8
 8003788:	6809      	ldr	r1, [r1, #0]
 800378a:	f421 3180 	bic.w	r1, r1, #65536	@ 0x10000
 800378e:	4a1f      	ldr	r2, [pc, #124]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 8003790:	3208      	adds	r2, #8
 8003792:	6011      	str	r1, [r2, #0]
 8003794:	1f11      	subs	r1, r2, #4
 8003796:	6809      	ldr	r1, [r1, #0]
 8003798:	f421 3180 	bic.w	r1, r1, #65536	@ 0x10000
 800379c:	1f12      	subs	r2, r2, #4
 800379e:	6011      	str	r1, [r2, #0]
 80037a0:	6841      	ldr	r1, [r0, #4]
 80037a2:	f401 3180 	and.w	r1, r1, #65536	@ 0x10000
 80037a6:	f5b1 3f80 	cmp.w	r1, #65536	@ 0x10000
 80037aa:	d107      	bne.n	80037bc <HAL_PWR_ConfigPVD+0x60>
 80037ac:	4917      	ldr	r1, [pc, #92]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 80037ae:	1f09      	subs	r1, r1, #4
 80037b0:	6809      	ldr	r1, [r1, #0]
 80037b2:	f441 3180 	orr.w	r1, r1, #65536	@ 0x10000
 80037b6:	4a15      	ldr	r2, [pc, #84]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 80037b8:	1f12      	subs	r2, r2, #4
 80037ba:	6011      	str	r1, [r2, #0]
 80037bc:	6841      	ldr	r1, [r0, #4]
 80037be:	f401 3100 	and.w	r1, r1, #131072	@ 0x20000
 80037c2:	f5b1 3f00 	cmp.w	r1, #131072	@ 0x20000
 80037c6:	d105      	bne.n	80037d4 <HAL_PWR_ConfigPVD+0x78>
 80037c8:	4910      	ldr	r1, [pc, #64]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 80037ca:	6809      	ldr	r1, [r1, #0]
 80037cc:	f441 3180 	orr.w	r1, r1, #65536	@ 0x10000
 80037d0:	4a0e      	ldr	r2, [pc, #56]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 80037d2:	6011      	str	r1, [r2, #0]
 80037d4:	7901      	ldrb	r1, [r0, #4]
 80037d6:	f001 0101 	and.w	r1, r1, #1
 80037da:	b139      	cbz	r1, 80037ec <HAL_PWR_ConfigPVD+0x90>
 80037dc:	490b      	ldr	r1, [pc, #44]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 80037de:	1d09      	adds	r1, r1, #4
 80037e0:	6809      	ldr	r1, [r1, #0]
 80037e2:	f441 3180 	orr.w	r1, r1, #65536	@ 0x10000
 80037e6:	4a09      	ldr	r2, [pc, #36]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 80037e8:	1d12      	adds	r2, r2, #4
 80037ea:	6011      	str	r1, [r2, #0]
 80037ec:	7901      	ldrb	r1, [r0, #4]
 80037ee:	f001 0102 	and.w	r1, r1, #2
 80037f2:	2902      	cmp	r1, #2
 80037f4:	d107      	bne.n	8003806 <HAL_PWR_ConfigPVD+0xaa>
 80037f6:	4905      	ldr	r1, [pc, #20]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 80037f8:	3108      	adds	r1, #8
 80037fa:	6809      	ldr	r1, [r1, #0]
 80037fc:	f441 3180 	orr.w	r1, r1, #65536	@ 0x10000
 8003800:	4a02      	ldr	r2, [pc, #8]	@ (800380c <HAL_PWR_ConfigPVD+0xb0>)
 8003802:	3208      	adds	r2, #8
 8003804:	6011      	str	r1, [r2, #0]
 8003806:	4770      	bx	lr
 8003808:	40007000 	.word	0x40007000
 800380c:	40010404 	.word	0x40010404

08003810 <HAL_PWR_DeInit>:
 8003810:	4805      	ldr	r0, [pc, #20]	@ (8003828 <HAL_PWR_DeInit+0x18>)
 8003812:	6900      	ldr	r0, [r0, #16]
 8003814:	f040 5080 	orr.w	r0, r0, #268435456	@ 0x10000000
 8003818:	4903      	ldr	r1, [pc, #12]	@ (8003828 <HAL_PWR_DeInit+0x18>)
 800381a:	6108      	str	r0, [r1, #16]
 800381c:	4608      	mov	r0, r1
 800381e:	6900      	ldr	r0, [r0, #16]
 8003820:	f020 5080 	bic.w	r0, r0, #268435456	@ 0x10000000
 8003824:	6108      	str	r0, [r1, #16]
 8003826:	4770      	bx	lr
 8003828:	40021000 	.word	0x40021000

0800382c <HAL_PWR_DisableBkUpAccess>:
 800382c:	2000      	movs	r0, #0
 800382e:	4901      	ldr	r1, [pc, #4]	@ (8003834 <HAL_PWR_DisableBkUpAccess+0x8>)
 8003830:	6208      	str	r0, [r1, #32]
 8003832:	4770      	bx	lr
 8003834:	420e0000 	.word	0x420e0000

08003838 <HAL_PWR_DisablePVD>:
 8003838:	2000      	movs	r0, #0
 800383a:	4901      	ldr	r1, [pc, #4]	@ (8003840 <HAL_PWR_DisablePVD+0x8>)
 800383c:	6108      	str	r0, [r1, #16]
 800383e:	4770      	bx	lr
 8003840:	420e0000 	.word	0x420e0000

08003844 <HAL_PWR_DisableSEVOnPend>:
 8003844:	4803      	ldr	r0, [pc, #12]	@ (8003854 <HAL_PWR_DisableSEVOnPend+0x10>)
 8003846:	6800      	ldr	r0, [r0, #0]
 8003848:	f020 0010 	bic.w	r0, r0, #16
 800384c:	4901      	ldr	r1, [pc, #4]	@ (8003854 <HAL_PWR_DisableSEVOnPend+0x10>)
 800384e:	6008      	str	r0, [r1, #0]
 8003850:	4770      	bx	lr
 8003852:	0000      	.short	0x0000
 8003854:	e000ed10 	.word	0xe000ed10

08003858 <HAL_PWR_DisableSleepOnExit>:
 8003858:	4803      	ldr	r0, [pc, #12]	@ (8003868 <HAL_PWR_DisableSleepOnExit+0x10>)
 800385a:	6800      	ldr	r0, [r0, #0]
 800385c:	f020 0002 	bic.w	r0, r0, #2
 8003860:	4901      	ldr	r1, [pc, #4]	@ (8003868 <HAL_PWR_DisableSleepOnExit+0x10>)
 8003862:	6008      	str	r0, [r1, #0]
 8003864:	4770      	bx	lr
 8003866:	0000      	.short	0x0000
 8003868:	e000ed10 	.word	0xe000ed10

0800386c <HAL_PWR_DisableWakeUpPin>:
 800386c:	2100      	movs	r1, #0
 800386e:	fa90 f2a0 	rbit	r2, r0
 8003872:	fab2 f282 	clz	r2, r2
 8003876:	4b03      	ldr	r3, [pc, #12]	@ (8003884 <HAL_PWR_DisableWakeUpPin+0x18>)
 8003878:	eb03 0282 	add.w	r2, r3, r2, lsl #2
 800387c:	f8c2 1080 	str.w	r1, [r2, #128]	@ 0x80
 8003880:	4770      	bx	lr
 8003882:	0000      	.short	0x0000
 8003884:	420e0000 	.word	0x420e0000

08003888 <HAL_PWR_EnableBkUpAccess>:
 8003888:	2001      	movs	r0, #1
 800388a:	4901      	ldr	r1, [pc, #4]	@ (8003890 <HAL_PWR_EnableBkUpAccess+0x8>)
 800388c:	6208      	str	r0, [r1, #32]
 800388e:	4770      	bx	lr
 8003890:	420e0000 	.word	0x420e0000

08003894 <HAL_PWR_EnablePVD>:
 8003894:	2001      	movs	r0, #1
 8003896:	4901      	ldr	r1, [pc, #4]	@ (800389c <HAL_PWR_EnablePVD+0x8>)
 8003898:	6108      	str	r0, [r1, #16]
 800389a:	4770      	bx	lr
 800389c:	420e0000 	.word	0x420e0000

080038a0 <HAL_PWR_EnableSEVOnPend>:
 80038a0:	4803      	ldr	r0, [pc, #12]	@ (80038b0 <HAL_PWR_EnableSEVOnPend+0x10>)
 80038a2:	6800      	ldr	r0, [r0, #0]
 80038a4:	f040 0010 	orr.w	r0, r0, #16
 80038a8:	4901      	ldr	r1, [pc, #4]	@ (80038b0 <HAL_PWR_EnableSEVOnPend+0x10>)
 80038aa:	6008      	str	r0, [r1, #0]
 80038ac:	4770      	bx	lr
 80038ae:	0000      	.short	0x0000
 80038b0:	e000ed10 	.word	0xe000ed10

080038b4 <HAL_PWR_EnableSleepOnExit>:
 80038b4:	4803      	ldr	r0, [pc, #12]	@ (80038c4 <HAL_PWR_EnableSleepOnExit+0x10>)
 80038b6:	6800      	ldr	r0, [r0, #0]
 80038b8:	f040 0002 	orr.w	r0, r0, #2
 80038bc:	4901      	ldr	r1, [pc, #4]	@ (80038c4 <HAL_PWR_EnableSleepOnExit+0x10>)
 80038be:	6008      	str	r0, [r1, #0]
 80038c0:	4770      	bx	lr
 80038c2:	0000      	.short	0x0000
 80038c4:	e000ed10 	.word	0xe000ed10

080038c8 <HAL_PWR_EnableWakeUpPin>:
 80038c8:	2101      	movs	r1, #1
 80038ca:	fa90 f2a0 	rbit	r2, r0
 80038ce:	fab2 f282 	clz	r2, r2
 80038d2:	4b03      	ldr	r3, [pc, #12]	@ (80038e0 <HAL_PWR_EnableWakeUpPin+0x18>)
 80038d4:	eb03 0282 	add.w	r2, r3, r2, lsl #2
 80038d8:	f8c2 1080 	str.w	r1, [r2, #128]	@ 0x80
 80038dc:	4770      	bx	lr
 80038de:	0000      	.short	0x0000
 80038e0:	420e0000 	.word	0x420e0000

080038e4 <HAL_PWR_EnterSLEEPMode>:
 80038e4:	4a06      	ldr	r2, [pc, #24]	@ (8003900 <HAL_PWR_EnterSLEEPMode+0x1c>)
 80038e6:	6812      	ldr	r2, [r2, #0]
 80038e8:	f022 0204 	bic.w	r2, r2, #4
 80038ec:	4b04      	ldr	r3, [pc, #16]	@ (8003900 <HAL_PWR_EnterSLEEPMode+0x1c>)
 80038ee:	601a      	str	r2, [r3, #0]
 80038f0:	2901      	cmp	r1, #1
 80038f2:	d101      	bne.n	80038f8 <HAL_PWR_EnterSLEEPMode+0x14>
 80038f4:	bf30      	wfi
 80038f6:	e002      	b.n	80038fe <HAL_PWR_EnterSLEEPMode+0x1a>
 80038f8:	bf40      	sev
 80038fa:	bf20      	wfe
 80038fc:	bf20      	wfe
 80038fe:	4770      	bx	lr
 8003900:	e000ed10 	.word	0xe000ed10

08003904 <HAL_PWR_EnterSTANDBYMode>:
 8003904:	4807      	ldr	r0, [pc, #28]	@ (8003924 <HAL_PWR_EnterSTANDBYMode+0x20>)
 8003906:	6800      	ldr	r0, [r0, #0]
 8003908:	f040 0002 	orr.w	r0, r0, #2
 800390c:	4905      	ldr	r1, [pc, #20]	@ (8003924 <HAL_PWR_EnterSTANDBYMode+0x20>)
 800390e:	6008      	str	r0, [r1, #0]
 8003910:	4805      	ldr	r0, [pc, #20]	@ (8003928 <HAL_PWR_EnterSTANDBYMode+0x24>)
 8003912:	6800      	ldr	r0, [r0, #0]
 8003914:	f040 0004 	orr.w	r0, r0, #4
 8003918:	4903      	ldr	r1, [pc, #12]	@ (8003928 <HAL_PWR_EnterSTANDBYMode+0x24>)
 800391a:	6008      	str	r0, [r1, #0]
 800391c:	bf00      	nop
 800391e:	bf00      	nop
 8003920:	bf30      	wfi
 8003922:	4770      	bx	lr
 8003924:	40007000 	.word	0x40007000
 8003928:	e000ed10 	.word	0xe000ed10

0800392c <HAL_PWR_EnterSTOPMode>:
 800392c:	b570      	push	{r4, r5, r6, lr}
 800392e:	4604      	mov	r4, r0
 8003930:	460d      	mov	r5, r1
 8003932:	4811      	ldr	r0, [pc, #68]	@ (8003978 <HAL_PWR_EnterSTOPMode+0x4c>)
 8003934:	6800      	ldr	r0, [r0, #0]
 8003936:	f020 0002 	bic.w	r0, r0, #2
 800393a:	490f      	ldr	r1, [pc, #60]	@ (8003978 <HAL_PWR_EnterSTOPMode+0x4c>)
 800393c:	6008      	str	r0, [r1, #0]
 800393e:	4608      	mov	r0, r1
 8003940:	6800      	ldr	r0, [r0, #0]
 8003942:	f020 0001 	bic.w	r0, r0, #1
 8003946:	4320      	orrs	r0, r4
 8003948:	6008      	str	r0, [r1, #0]
 800394a:	480c      	ldr	r0, [pc, #48]	@ (800397c <HAL_PWR_EnterSTOPMode+0x50>)
 800394c:	6800      	ldr	r0, [r0, #0]
 800394e:	f040 0004 	orr.w	r0, r0, #4
 8003952:	490a      	ldr	r1, [pc, #40]	@ (800397c <HAL_PWR_EnterSTOPMode+0x50>)
 8003954:	6008      	str	r0, [r1, #0]
 8003956:	2d01      	cmp	r5, #1
 8003958:	d101      	bne.n	800395e <HAL_PWR_EnterSTOPMode+0x32>
 800395a:	bf30      	wfi
 800395c:	e004      	b.n	8003968 <HAL_PWR_EnterSTOPMode+0x3c>
 800395e:	bf40      	sev
 8003960:	f001 fed6 	bl	8005710 <PWR_OverloadWfe>
 8003964:	f001 fed4 	bl	8005710 <PWR_OverloadWfe>
 8003968:	4804      	ldr	r0, [pc, #16]	@ (800397c <HAL_PWR_EnterSTOPMode+0x50>)
 800396a:	6800      	ldr	r0, [r0, #0]
 800396c:	f020 0004 	bic.w	r0, r0, #4
 8003970:	4902      	ldr	r1, [pc, #8]	@ (800397c <HAL_PWR_EnterSTOPMode+0x50>)
 8003972:	6008      	str	r0, [r1, #0]
 8003974:	bd70      	pop	{r4, r5, r6, pc}
 8003976:	0000      	.short	0x0000
 8003978:	40007000 	.word	0x40007000
 800397c:	e000ed10 	.word	0xe000ed10

08003980 <HAL_PWR_PVDCallback>:
 8003980:	4770      	bx	lr
	...

08003984 <HAL_PWR_PVD_IRQHandler>:
 8003984:	b510      	push	{r4, lr}
 8003986:	4806      	ldr	r0, [pc, #24]	@ (80039a0 <HAL_PWR_PVD_IRQHandler+0x1c>)
 8003988:	6800      	ldr	r0, [r0, #0]
 800398a:	f400 3080 	and.w	r0, r0, #65536	@ 0x10000
 800398e:	b128      	cbz	r0, 800399c <HAL_PWR_PVD_IRQHandler+0x18>
 8003990:	f7ff fff6 	bl	8003980 <HAL_PWR_PVDCallback>
 8003994:	f44f 3080 	mov.w	r0, #65536	@ 0x10000
 8003998:	4901      	ldr	r1, [pc, #4]	@ (80039a0 <HAL_PWR_PVD_IRQHandler+0x1c>)
 800399a:	6008      	str	r0, [r1, #0]
 800399c:	bd10      	pop	{r4, pc}
 800399e:	0000      	.short	0x0000
 80039a0:	40010414 	.word	0x40010414

080039a4 <HAL_RCCEx_GetPeriphCLKConfig>:
 80039a4:	2100      	movs	r1, #0
 80039a6:	2201      	movs	r2, #1
 80039a8:	6002      	str	r2, [r0, #0]
 80039aa:	4a12      	ldr	r2, [pc, #72]	@ (80039f4 <HAL_RCCEx_GetPeriphCLKConfig+0x50>)
 80039ac:	6a12      	ldr	r2, [r2, #32]
 80039ae:	f402 7140 	and.w	r1, r2, #768	@ 0x300
 80039b2:	6041      	str	r1, [r0, #4]
 80039b4:	6802      	ldr	r2, [r0, #0]
 80039b6:	f042 0202 	orr.w	r2, r2, #2
 80039ba:	6002      	str	r2, [r0, #0]
 80039bc:	4a0d      	ldr	r2, [pc, #52]	@ (80039f4 <HAL_RCCEx_GetPeriphCLKConfig+0x50>)
 80039be:	6852      	ldr	r2, [r2, #4]
 80039c0:	f402 4240 	and.w	r2, r2, #49152	@ 0xc000
 80039c4:	6082      	str	r2, [r0, #8]
 80039c6:	6802      	ldr	r2, [r0, #0]
 80039c8:	f042 0204 	orr.w	r2, r2, #4
 80039cc:	6002      	str	r2, [r0, #0]
 80039ce:	2200      	movs	r2, #0
 80039d0:	60c2      	str	r2, [r0, #12]
 80039d2:	6802      	ldr	r2, [r0, #0]
 80039d4:	f042 0208 	orr.w	r2, r2, #8
 80039d8:	6002      	str	r2, [r0, #0]
 80039da:	2200      	movs	r2, #0
 80039dc:	6102      	str	r2, [r0, #16]
 80039de:	6802      	ldr	r2, [r0, #0]
 80039e0:	f042 0210 	orr.w	r2, r2, #16
 80039e4:	6002      	str	r2, [r0, #0]
 80039e6:	4a03      	ldr	r2, [pc, #12]	@ (80039f4 <HAL_RCCEx_GetPeriphCLKConfig+0x50>)
 80039e8:	6852      	ldr	r2, [r2, #4]
 80039ea:	f402 0280 	and.w	r2, r2, #4194304	@ 0x400000
 80039ee:	6142      	str	r2, [r0, #20]
 80039f0:	4770      	bx	lr
 80039f2:	0000      	.short	0x0000
 80039f4:	40021000 	.word	0x40021000

080039f8 <HAL_RCCEx_GetPeriphCLKFreq>:
 80039f8:	e92d 47f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, lr}
 80039fc:	4606      	mov	r6, r0
 80039fe:	f04f 0800 	mov.w	r8, #0
 8003a02:	2500      	movs	r5, #0
 8003a04:	2700      	movs	r7, #0
 8003a06:	2400      	movs	r4, #0
 8003a08:	46a1      	mov	r9, r4
 8003a0a:	2e04      	cmp	r6, #4
 8003a0c:	d037      	beq.n	8003a7e <HAL_RCCEx_GetPeriphCLKFreq+0x86>
 8003a0e:	dc04      	bgt.n	8003a1a <HAL_RCCEx_GetPeriphCLKFreq+0x22>
 8003a10:	2e01      	cmp	r6, #1
 8003a12:	d03c      	beq.n	8003a8e <HAL_RCCEx_GetPeriphCLKFreq+0x96>
 8003a14:	2e02      	cmp	r6, #2
 8003a16:	d16c      	bne.n	8003af2 <HAL_RCCEx_GetPeriphCLKFreq+0xfa>
 8003a18:	e060      	b.n	8003adc <HAL_RCCEx_GetPeriphCLKFreq+0xe4>
 8003a1a:	2e08      	cmp	r6, #8
 8003a1c:	d033      	beq.n	8003a86 <HAL_RCCEx_GetPeriphCLKFreq+0x8e>
 8003a1e:	2e10      	cmp	r6, #16
 8003a20:	d167      	bne.n	8003af2 <HAL_RCCEx_GetPeriphCLKFreq+0xfa>
 8003a22:	4836      	ldr	r0, [pc, #216]	@ (8003afc <HAL_RCCEx_GetPeriphCLKFreq+0x104>)
 8003a24:	6844      	ldr	r4, [r0, #4]
 8003a26:	6800      	ldr	r0, [r0, #0]
 8003a28:	f000 7080 	and.w	r0, r0, #16777216	@ 0x1000000
 8003a2c:	b308      	cbz	r0, 8003a72 <HAL_RCCEx_GetPeriphCLKFreq+0x7a>
 8003a2e:	4834      	ldr	r0, [pc, #208]	@ (8003b00 <HAL_RCCEx_GetPeriphCLKFreq+0x108>)
 8003a30:	f3c4 4183 	ubfx	r1, r4, #18, #4
 8003a34:	5c47      	ldrb	r7, [r0, r1]
 8003a36:	f404 3080 	and.w	r0, r4, #65536	@ 0x10000
 8003a3a:	b178      	cbz	r0, 8003a5c <HAL_RCCEx_GetPeriphCLKFreq+0x64>
 8003a3c:	482f      	ldr	r0, [pc, #188]	@ (8003afc <HAL_RCCEx_GetPeriphCLKFreq+0x104>)
 8003a3e:	6840      	ldr	r0, [r0, #4]
 8003a40:	f3c0 4040 	ubfx	r0, r0, #17, #1
 8003a44:	492f      	ldr	r1, [pc, #188]	@ (8003b04 <HAL_RCCEx_GetPeriphCLKFreq+0x10c>)
 8003a46:	f811 8000 	ldrb.w	r8, [r1, r0]
 8003a4a:	f404 3080 	and.w	r0, r4, #65536	@ 0x10000
 8003a4e:	b140      	cbz	r0, 8003a62 <HAL_RCCEx_GetPeriphCLKFreq+0x6a>
 8003a50:	482d      	ldr	r0, [pc, #180]	@ (8003b08 <HAL_RCCEx_GetPeriphCLKFreq+0x110>)
 8003a52:	fbb0 f0f8 	udiv	r0, r0, r8
 8003a56:	fb00 f507 	mul.w	r5, r0, r7
 8003a5a:	e002      	b.n	8003a62 <HAL_RCCEx_GetPeriphCLKFreq+0x6a>
 8003a5c:	482b      	ldr	r0, [pc, #172]	@ (8003b0c <HAL_RCCEx_GetPeriphCLKFreq+0x114>)
 8003a5e:	fb07 f500 	mul.w	r5, r7, r0
 8003a62:	4826      	ldr	r0, [pc, #152]	@ (8003afc <HAL_RCCEx_GetPeriphCLKFreq+0x104>)
 8003a64:	6840      	ldr	r0, [r0, #4]
 8003a66:	f400 0080 	and.w	r0, r0, #4194304	@ 0x400000
 8003a6a:	f5b0 0f80 	cmp.w	r0, #4194304	@ 0x400000
 8003a6e:	d101      	bne.n	8003a74 <HAL_RCCEx_GetPeriphCLKFreq+0x7c>
 8003a70:	46a9      	mov	r9, r5
 8003a72:	e003      	b.n	8003a7c <HAL_RCCEx_GetPeriphCLKFreq+0x84>
 8003a74:	0068      	lsls	r0, r5, #1
 8003a76:	2103      	movs	r1, #3
 8003a78:	fbb0 f9f1 	udiv	r9, r0, r1
 8003a7c:	e03a      	b.n	8003af4 <HAL_RCCEx_GetPeriphCLKFreq+0xfc>
 8003a7e:	f000 fae7 	bl	8004050 <HAL_RCC_GetSysClockFreq>
 8003a82:	4681      	mov	r9, r0
 8003a84:	e036      	b.n	8003af4 <HAL_RCCEx_GetPeriphCLKFreq+0xfc>
 8003a86:	f000 fae3 	bl	8004050 <HAL_RCC_GetSysClockFreq>
 8003a8a:	4681      	mov	r9, r0
 8003a8c:	e032      	b.n	8003af4 <HAL_RCCEx_GetPeriphCLKFreq+0xfc>
 8003a8e:	481b      	ldr	r0, [pc, #108]	@ (8003afc <HAL_RCCEx_GetPeriphCLKFreq+0x104>)
 8003a90:	6a04      	ldr	r4, [r0, #32]
 8003a92:	f404 7040 	and.w	r0, r4, #768	@ 0x300
 8003a96:	f5b0 7f80 	cmp.w	r0, #256	@ 0x100
 8003a9a:	d105      	bne.n	8003aa8 <HAL_RCCEx_GetPeriphCLKFreq+0xb0>
 8003a9c:	f004 0002 	and.w	r0, r4, #2
 8003aa0:	b110      	cbz	r0, 8003aa8 <HAL_RCCEx_GetPeriphCLKFreq+0xb0>
 8003aa2:	f44f 4900 	mov.w	r9, #32768	@ 0x8000
 8003aa6:	e018      	b.n	8003ada <HAL_RCCEx_GetPeriphCLKFreq+0xe2>
 8003aa8:	f404 7040 	and.w	r0, r4, #768	@ 0x300
 8003aac:	f5b0 7f00 	cmp.w	r0, #512	@ 0x200
 8003ab0:	d107      	bne.n	8003ac2 <HAL_RCCEx_GetPeriphCLKFreq+0xca>
 8003ab2:	4812      	ldr	r0, [pc, #72]	@ (8003afc <HAL_RCCEx_GetPeriphCLKFreq+0x104>)
 8003ab4:	6a40      	ldr	r0, [r0, #36]	@ 0x24
 8003ab6:	f000 0002 	and.w	r0, r0, #2
 8003aba:	b110      	cbz	r0, 8003ac2 <HAL_RCCEx_GetPeriphCLKFreq+0xca>
 8003abc:	f649 4940 	movw	r9, #40000	@ 0x9c40
 8003ac0:	e00b      	b.n	8003ada <HAL_RCCEx_GetPeriphCLKFreq+0xe2>
 8003ac2:	f404 7040 	and.w	r0, r4, #768	@ 0x300
 8003ac6:	f5b0 7f40 	cmp.w	r0, #768	@ 0x300
 8003aca:	d106      	bne.n	8003ada <HAL_RCCEx_GetPeriphCLKFreq+0xe2>
 8003acc:	480b      	ldr	r0, [pc, #44]	@ (8003afc <HAL_RCCEx_GetPeriphCLKFreq+0x104>)
 8003ace:	6800      	ldr	r0, [r0, #0]
 8003ad0:	f400 3000 	and.w	r0, r0, #131072	@ 0x20000
 8003ad4:	b108      	cbz	r0, 8003ada <HAL_RCCEx_GetPeriphCLKFreq+0xe2>
 8003ad6:	f24f 4924 	movw	r9, #62500	@ 0xf424
 8003ada:	e00b      	b.n	8003af4 <HAL_RCCEx_GetPeriphCLKFreq+0xfc>
 8003adc:	f000 faa8 	bl	8004030 <HAL_RCC_GetPCLK2Freq>
 8003ae0:	4906      	ldr	r1, [pc, #24]	@ (8003afc <HAL_RCCEx_GetPeriphCLKFreq+0x104>)
 8003ae2:	6849      	ldr	r1, [r1, #4]
 8003ae4:	f3c1 3181 	ubfx	r1, r1, #14, #2
 8003ae8:	1c49      	adds	r1, r1, #1
 8003aea:	0049      	lsls	r1, r1, #1
 8003aec:	fbb0 f9f1 	udiv	r9, r0, r1
 8003af0:	e000      	b.n	8003af4 <HAL_RCCEx_GetPeriphCLKFreq+0xfc>
 8003af2:	bf00      	nop
 8003af4:	bf00      	nop
 8003af6:	4648      	mov	r0, r9
 8003af8:	e8bd 87f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, pc}
 8003afc:	40021000 	.word	0x40021000
 8003b00:	08006c97 	.word	0x08006c97
 8003b04:	08006ca7 	.word	0x08006ca7
 8003b08:	007a1200 	.word	0x007a1200
 8003b0c:	003d0900 	.word	0x003d0900

08003b10 <HAL_RCCEx_PeriphCLKConfig>:
 8003b10:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8003b12:	4604      	mov	r4, r0
 8003b14:	2600      	movs	r6, #0
 8003b16:	2500      	movs	r5, #0
 8003b18:	7820      	ldrb	r0, [r4, #0]
 8003b1a:	f000 0001 	and.w	r0, r0, #1
 8003b1e:	2800      	cmp	r0, #0
 8003b20:	d06b      	beq.n	8003bfa <HAL_RCCEx_PeriphCLKConfig+0xea>
 8003b22:	2700      	movs	r7, #0
 8003b24:	4843      	ldr	r0, [pc, #268]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003b26:	69c0      	ldr	r0, [r0, #28]
 8003b28:	f000 5080 	and.w	r0, r0, #268435456	@ 0x10000000
 8003b2c:	b970      	cbnz	r0, 8003b4c <HAL_RCCEx_PeriphCLKConfig+0x3c>
 8003b2e:	bf00      	nop
 8003b30:	4840      	ldr	r0, [pc, #256]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003b32:	69c0      	ldr	r0, [r0, #28]
 8003b34:	f040 5080 	orr.w	r0, r0, #268435456	@ 0x10000000
 8003b38:	493e      	ldr	r1, [pc, #248]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003b3a:	61c8      	str	r0, [r1, #28]
 8003b3c:	4608      	mov	r0, r1
 8003b3e:	69c0      	ldr	r0, [r0, #28]
 8003b40:	f000 5080 	and.w	r0, r0, #268435456	@ 0x10000000
 8003b44:	9000      	str	r0, [sp, #0]
 8003b46:	bf00      	nop
 8003b48:	bf00      	nop
 8003b4a:	2701      	movs	r7, #1
 8003b4c:	483a      	ldr	r0, [pc, #232]	@ (8003c38 <HAL_RCCEx_PeriphCLKConfig+0x128>)
 8003b4e:	6800      	ldr	r0, [r0, #0]
 8003b50:	f400 7080 	and.w	r0, r0, #256	@ 0x100
 8003b54:	b9b0      	cbnz	r0, 8003b84 <HAL_RCCEx_PeriphCLKConfig+0x74>
 8003b56:	4838      	ldr	r0, [pc, #224]	@ (8003c38 <HAL_RCCEx_PeriphCLKConfig+0x128>)
 8003b58:	6800      	ldr	r0, [r0, #0]
 8003b5a:	f440 7080 	orr.w	r0, r0, #256	@ 0x100
 8003b5e:	4936      	ldr	r1, [pc, #216]	@ (8003c38 <HAL_RCCEx_PeriphCLKConfig+0x128>)
 8003b60:	6008      	str	r0, [r1, #0]
 8003b62:	f7ff fa89 	bl	8003078 <HAL_GetTick>
 8003b66:	4606      	mov	r6, r0
 8003b68:	e006      	b.n	8003b78 <HAL_RCCEx_PeriphCLKConfig+0x68>
 8003b6a:	f7ff fa85 	bl	8003078 <HAL_GetTick>
 8003b6e:	1b80      	subs	r0, r0, r6
 8003b70:	2864      	cmp	r0, #100	@ 0x64
 8003b72:	d901      	bls.n	8003b78 <HAL_RCCEx_PeriphCLKConfig+0x68>
 8003b74:	2003      	movs	r0, #3
 8003b76:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 8003b78:	482f      	ldr	r0, [pc, #188]	@ (8003c38 <HAL_RCCEx_PeriphCLKConfig+0x128>)
 8003b7a:	6800      	ldr	r0, [r0, #0]
 8003b7c:	f400 7080 	and.w	r0, r0, #256	@ 0x100
 8003b80:	2800      	cmp	r0, #0
 8003b82:	d0f2      	beq.n	8003b6a <HAL_RCCEx_PeriphCLKConfig+0x5a>
 8003b84:	482b      	ldr	r0, [pc, #172]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003b86:	6a00      	ldr	r0, [r0, #32]
 8003b88:	f400 7540 	and.w	r5, r0, #768	@ 0x300
 8003b8c:	b32d      	cbz	r5, 8003bda <HAL_RCCEx_PeriphCLKConfig+0xca>
 8003b8e:	88a0      	ldrh	r0, [r4, #4]
 8003b90:	f400 7040 	and.w	r0, r0, #768	@ 0x300
 8003b94:	42a8      	cmp	r0, r5
 8003b96:	d020      	beq.n	8003bda <HAL_RCCEx_PeriphCLKConfig+0xca>
 8003b98:	4826      	ldr	r0, [pc, #152]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003b9a:	6a00      	ldr	r0, [r0, #32]
 8003b9c:	f420 7540 	bic.w	r5, r0, #768	@ 0x300
 8003ba0:	2001      	movs	r0, #1
 8003ba2:	4926      	ldr	r1, [pc, #152]	@ (8003c3c <HAL_RCCEx_PeriphCLKConfig+0x12c>)
 8003ba4:	6008      	str	r0, [r1, #0]
 8003ba6:	2000      	movs	r0, #0
 8003ba8:	6008      	str	r0, [r1, #0]
 8003baa:	4822      	ldr	r0, [pc, #136]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003bac:	6205      	str	r5, [r0, #32]
 8003bae:	f005 0001 	and.w	r0, r5, #1
 8003bb2:	b190      	cbz	r0, 8003bda <HAL_RCCEx_PeriphCLKConfig+0xca>
 8003bb4:	f7ff fa60 	bl	8003078 <HAL_GetTick>
 8003bb8:	4606      	mov	r6, r0
 8003bba:	e008      	b.n	8003bce <HAL_RCCEx_PeriphCLKConfig+0xbe>
 8003bbc:	f7ff fa5c 	bl	8003078 <HAL_GetTick>
 8003bc0:	1b80      	subs	r0, r0, r6
 8003bc2:	f241 3188 	movw	r1, #5000	@ 0x1388
 8003bc6:	4288      	cmp	r0, r1
 8003bc8:	d901      	bls.n	8003bce <HAL_RCCEx_PeriphCLKConfig+0xbe>
 8003bca:	2003      	movs	r0, #3
 8003bcc:	e7d3      	b.n	8003b76 <HAL_RCCEx_PeriphCLKConfig+0x66>
 8003bce:	4819      	ldr	r0, [pc, #100]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003bd0:	6a00      	ldr	r0, [r0, #32]
 8003bd2:	f000 0002 	and.w	r0, r0, #2
 8003bd6:	2800      	cmp	r0, #0
 8003bd8:	d0f0      	beq.n	8003bbc <HAL_RCCEx_PeriphCLKConfig+0xac>
 8003bda:	4816      	ldr	r0, [pc, #88]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003bdc:	6a00      	ldr	r0, [r0, #32]
 8003bde:	f420 7040 	bic.w	r0, r0, #768	@ 0x300
 8003be2:	6861      	ldr	r1, [r4, #4]
 8003be4:	4308      	orrs	r0, r1
 8003be6:	4913      	ldr	r1, [pc, #76]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003be8:	6208      	str	r0, [r1, #32]
 8003bea:	2f01      	cmp	r7, #1
 8003bec:	d104      	bne.n	8003bf8 <HAL_RCCEx_PeriphCLKConfig+0xe8>
 8003bee:	4608      	mov	r0, r1
 8003bf0:	69c0      	ldr	r0, [r0, #28]
 8003bf2:	f020 5080 	bic.w	r0, r0, #268435456	@ 0x10000000
 8003bf6:	61c8      	str	r0, [r1, #28]
 8003bf8:	bf00      	nop
 8003bfa:	7820      	ldrb	r0, [r4, #0]
 8003bfc:	f000 0002 	and.w	r0, r0, #2
 8003c00:	2802      	cmp	r0, #2
 8003c02:	d107      	bne.n	8003c14 <HAL_RCCEx_PeriphCLKConfig+0x104>
 8003c04:	480b      	ldr	r0, [pc, #44]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003c06:	6840      	ldr	r0, [r0, #4]
 8003c08:	f420 4040 	bic.w	r0, r0, #49152	@ 0xc000
 8003c0c:	68a1      	ldr	r1, [r4, #8]
 8003c0e:	4308      	orrs	r0, r1
 8003c10:	4908      	ldr	r1, [pc, #32]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003c12:	6048      	str	r0, [r1, #4]
 8003c14:	7820      	ldrb	r0, [r4, #0]
 8003c16:	f000 0010 	and.w	r0, r0, #16
 8003c1a:	2810      	cmp	r0, #16
 8003c1c:	d107      	bne.n	8003c2e <HAL_RCCEx_PeriphCLKConfig+0x11e>
 8003c1e:	4805      	ldr	r0, [pc, #20]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003c20:	6840      	ldr	r0, [r0, #4]
 8003c22:	f420 0080 	bic.w	r0, r0, #4194304	@ 0x400000
 8003c26:	6961      	ldr	r1, [r4, #20]
 8003c28:	4308      	orrs	r0, r1
 8003c2a:	4902      	ldr	r1, [pc, #8]	@ (8003c34 <HAL_RCCEx_PeriphCLKConfig+0x124>)
 8003c2c:	6048      	str	r0, [r1, #4]
 8003c2e:	2000      	movs	r0, #0
 8003c30:	e7a1      	b.n	8003b76 <HAL_RCCEx_PeriphCLKConfig+0x66>
 8003c32:	0000      	.short	0x0000
 8003c34:	40021000 	.word	0x40021000
 8003c38:	40007000 	.word	0x40007000
 8003c3c:	42420440 	.word	0x42420440

08003c40 <HAL_RCC_CSSCallback>:
 8003c40:	4770      	bx	lr
	...

08003c44 <HAL_RCC_ClockConfig>:
 8003c44:	b570      	push	{r4, r5, r6, lr}
 8003c46:	4604      	mov	r4, r0
 8003c48:	460d      	mov	r5, r1
 8003c4a:	b90c      	cbnz	r4, 8003c50 <HAL_RCC_ClockConfig+0xc>
 8003c4c:	2001      	movs	r0, #1
 8003c4e:	bd70      	pop	{r4, r5, r6, pc}
 8003c50:	485a      	ldr	r0, [pc, #360]	@ (8003dbc <HAL_RCC_ClockConfig+0x178>)
 8003c52:	6800      	ldr	r0, [r0, #0]
 8003c54:	f000 0007 	and.w	r0, r0, #7
 8003c58:	42a8      	cmp	r0, r5
 8003c5a:	d20e      	bcs.n	8003c7a <HAL_RCC_ClockConfig+0x36>
 8003c5c:	4857      	ldr	r0, [pc, #348]	@ (8003dbc <HAL_RCC_ClockConfig+0x178>)
 8003c5e:	6800      	ldr	r0, [r0, #0]
 8003c60:	f020 0007 	bic.w	r0, r0, #7
 8003c64:	4328      	orrs	r0, r5
 8003c66:	4955      	ldr	r1, [pc, #340]	@ (8003dbc <HAL_RCC_ClockConfig+0x178>)
 8003c68:	6008      	str	r0, [r1, #0]
 8003c6a:	4608      	mov	r0, r1
 8003c6c:	6800      	ldr	r0, [r0, #0]
 8003c6e:	f000 0007 	and.w	r0, r0, #7
 8003c72:	42a8      	cmp	r0, r5
 8003c74:	d001      	beq.n	8003c7a <HAL_RCC_ClockConfig+0x36>
 8003c76:	2001      	movs	r0, #1
 8003c78:	e7e9      	b.n	8003c4e <HAL_RCC_ClockConfig+0xa>
 8003c7a:	7820      	ldrb	r0, [r4, #0]
 8003c7c:	f000 0002 	and.w	r0, r0, #2
 8003c80:	2802      	cmp	r0, #2
 8003c82:	d11d      	bne.n	8003cc0 <HAL_RCC_ClockConfig+0x7c>
 8003c84:	7820      	ldrb	r0, [r4, #0]
 8003c86:	f000 0004 	and.w	r0, r0, #4
 8003c8a:	2804      	cmp	r0, #4
 8003c8c:	d105      	bne.n	8003c9a <HAL_RCC_ClockConfig+0x56>
 8003c8e:	484c      	ldr	r0, [pc, #304]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003c90:	6840      	ldr	r0, [r0, #4]
 8003c92:	f440 60e0 	orr.w	r0, r0, #1792	@ 0x700
 8003c96:	494a      	ldr	r1, [pc, #296]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003c98:	6048      	str	r0, [r1, #4]
 8003c9a:	7820      	ldrb	r0, [r4, #0]
 8003c9c:	f000 0008 	and.w	r0, r0, #8
 8003ca0:	2808      	cmp	r0, #8
 8003ca2:	d105      	bne.n	8003cb0 <HAL_RCC_ClockConfig+0x6c>
 8003ca4:	4846      	ldr	r0, [pc, #280]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003ca6:	6840      	ldr	r0, [r0, #4]
 8003ca8:	f440 5060 	orr.w	r0, r0, #14336	@ 0x3800
 8003cac:	4944      	ldr	r1, [pc, #272]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003cae:	6048      	str	r0, [r1, #4]
 8003cb0:	4843      	ldr	r0, [pc, #268]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003cb2:	6840      	ldr	r0, [r0, #4]
 8003cb4:	f020 00f0 	bic.w	r0, r0, #240	@ 0xf0
 8003cb8:	68a1      	ldr	r1, [r4, #8]
 8003cba:	4308      	orrs	r0, r1
 8003cbc:	4940      	ldr	r1, [pc, #256]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003cbe:	6048      	str	r0, [r1, #4]
 8003cc0:	7820      	ldrb	r0, [r4, #0]
 8003cc2:	f000 0001 	and.w	r0, r0, #1
 8003cc6:	b378      	cbz	r0, 8003d28 <HAL_RCC_ClockConfig+0xe4>
 8003cc8:	6860      	ldr	r0, [r4, #4]
 8003cca:	2801      	cmp	r0, #1
 8003ccc:	d106      	bne.n	8003cdc <HAL_RCC_ClockConfig+0x98>
 8003cce:	483c      	ldr	r0, [pc, #240]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003cd0:	6800      	ldr	r0, [r0, #0]
 8003cd2:	f400 3000 	and.w	r0, r0, #131072	@ 0x20000
 8003cd6:	b990      	cbnz	r0, 8003cfe <HAL_RCC_ClockConfig+0xba>
 8003cd8:	2001      	movs	r0, #1
 8003cda:	e7b8      	b.n	8003c4e <HAL_RCC_ClockConfig+0xa>
 8003cdc:	6860      	ldr	r0, [r4, #4]
 8003cde:	2802      	cmp	r0, #2
 8003ce0:	d106      	bne.n	8003cf0 <HAL_RCC_ClockConfig+0xac>
 8003ce2:	4837      	ldr	r0, [pc, #220]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003ce4:	6800      	ldr	r0, [r0, #0]
 8003ce6:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 8003cea:	b940      	cbnz	r0, 8003cfe <HAL_RCC_ClockConfig+0xba>
 8003cec:	2001      	movs	r0, #1
 8003cee:	e7ae      	b.n	8003c4e <HAL_RCC_ClockConfig+0xa>
 8003cf0:	4833      	ldr	r0, [pc, #204]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003cf2:	6800      	ldr	r0, [r0, #0]
 8003cf4:	f000 0002 	and.w	r0, r0, #2
 8003cf8:	b908      	cbnz	r0, 8003cfe <HAL_RCC_ClockConfig+0xba>
 8003cfa:	2001      	movs	r0, #1
 8003cfc:	e7a7      	b.n	8003c4e <HAL_RCC_ClockConfig+0xa>
 8003cfe:	4830      	ldr	r0, [pc, #192]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003d00:	6840      	ldr	r0, [r0, #4]
 8003d02:	f020 0003 	bic.w	r0, r0, #3
 8003d06:	6861      	ldr	r1, [r4, #4]
 8003d08:	4308      	orrs	r0, r1
 8003d0a:	492d      	ldr	r1, [pc, #180]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003d0c:	6048      	str	r0, [r1, #4]
 8003d0e:	f7ff f9b3 	bl	8003078 <HAL_GetTick>
 8003d12:	4606      	mov	r6, r0
 8003d14:	e009      	b.n	8003d2a <HAL_RCC_ClockConfig+0xe6>
 8003d16:	f7ff f9af 	bl	8003078 <HAL_GetTick>
 8003d1a:	1b80      	subs	r0, r0, r6
 8003d1c:	f241 3188 	movw	r1, #5000	@ 0x1388
 8003d20:	4288      	cmp	r0, r1
 8003d22:	d902      	bls.n	8003d2a <HAL_RCC_ClockConfig+0xe6>
 8003d24:	2003      	movs	r0, #3
 8003d26:	e792      	b.n	8003c4e <HAL_RCC_ClockConfig+0xa>
 8003d28:	e007      	b.n	8003d3a <HAL_RCC_ClockConfig+0xf6>
 8003d2a:	4825      	ldr	r0, [pc, #148]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003d2c:	6840      	ldr	r0, [r0, #4]
 8003d2e:	f000 000c 	and.w	r0, r0, #12
 8003d32:	6861      	ldr	r1, [r4, #4]
 8003d34:	ebb0 0f81 	cmp.w	r0, r1, lsl #2
 8003d38:	d1ed      	bne.n	8003d16 <HAL_RCC_ClockConfig+0xd2>
 8003d3a:	4820      	ldr	r0, [pc, #128]	@ (8003dbc <HAL_RCC_ClockConfig+0x178>)
 8003d3c:	6800      	ldr	r0, [r0, #0]
 8003d3e:	f000 0007 	and.w	r0, r0, #7
 8003d42:	42a8      	cmp	r0, r5
 8003d44:	d90e      	bls.n	8003d64 <HAL_RCC_ClockConfig+0x120>
 8003d46:	481d      	ldr	r0, [pc, #116]	@ (8003dbc <HAL_RCC_ClockConfig+0x178>)
 8003d48:	6800      	ldr	r0, [r0, #0]
 8003d4a:	f020 0007 	bic.w	r0, r0, #7
 8003d4e:	4328      	orrs	r0, r5
 8003d50:	491a      	ldr	r1, [pc, #104]	@ (8003dbc <HAL_RCC_ClockConfig+0x178>)
 8003d52:	6008      	str	r0, [r1, #0]
 8003d54:	4608      	mov	r0, r1
 8003d56:	6800      	ldr	r0, [r0, #0]
 8003d58:	f000 0007 	and.w	r0, r0, #7
 8003d5c:	42a8      	cmp	r0, r5
 8003d5e:	d001      	beq.n	8003d64 <HAL_RCC_ClockConfig+0x120>
 8003d60:	2001      	movs	r0, #1
 8003d62:	e774      	b.n	8003c4e <HAL_RCC_ClockConfig+0xa>
 8003d64:	7820      	ldrb	r0, [r4, #0]
 8003d66:	f000 0004 	and.w	r0, r0, #4
 8003d6a:	2804      	cmp	r0, #4
 8003d6c:	d107      	bne.n	8003d7e <HAL_RCC_ClockConfig+0x13a>
 8003d6e:	4814      	ldr	r0, [pc, #80]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003d70:	6840      	ldr	r0, [r0, #4]
 8003d72:	f420 60e0 	bic.w	r0, r0, #1792	@ 0x700
 8003d76:	68e1      	ldr	r1, [r4, #12]
 8003d78:	4308      	orrs	r0, r1
 8003d7a:	4911      	ldr	r1, [pc, #68]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003d7c:	6048      	str	r0, [r1, #4]
 8003d7e:	7820      	ldrb	r0, [r4, #0]
 8003d80:	f000 0008 	and.w	r0, r0, #8
 8003d84:	2808      	cmp	r0, #8
 8003d86:	d108      	bne.n	8003d9a <HAL_RCC_ClockConfig+0x156>
 8003d88:	480d      	ldr	r0, [pc, #52]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003d8a:	6840      	ldr	r0, [r0, #4]
 8003d8c:	f420 5060 	bic.w	r0, r0, #14336	@ 0x3800
 8003d90:	6921      	ldr	r1, [r4, #16]
 8003d92:	ea40 00c1 	orr.w	r0, r0, r1, lsl #3
 8003d96:	490a      	ldr	r1, [pc, #40]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003d98:	6048      	str	r0, [r1, #4]
 8003d9a:	f000 f959 	bl	8004050 <HAL_RCC_GetSysClockFreq>
 8003d9e:	4908      	ldr	r1, [pc, #32]	@ (8003dc0 <HAL_RCC_ClockConfig+0x17c>)
 8003da0:	6849      	ldr	r1, [r1, #4]
 8003da2:	f3c1 1103 	ubfx	r1, r1, #4, #4
 8003da6:	4a07      	ldr	r2, [pc, #28]	@ (8003dc4 <HAL_RCC_ClockConfig+0x180>)
 8003da8:	5c51      	ldrb	r1, [r2, r1]
 8003daa:	40c8      	lsrs	r0, r1
 8003dac:	4906      	ldr	r1, [pc, #24]	@ (8003dc8 <HAL_RCC_ClockConfig+0x184>)
 8003dae:	6008      	str	r0, [r1, #0]
 8003db0:	4806      	ldr	r0, [pc, #24]	@ (8003dcc <HAL_RCC_ClockConfig+0x188>)
 8003db2:	6800      	ldr	r0, [r0, #0]
 8003db4:	f7ff fa26 	bl	8003204 <HAL_InitTick>
 8003db8:	2000      	movs	r0, #0
 8003dba:	e748      	b.n	8003c4e <HAL_RCC_ClockConfig+0xa>
 8003dbc:	40022000 	.word	0x40022000
 8003dc0:	40021000 	.word	0x40021000
 8003dc4:	08006ca9 	.word	0x08006ca9
 8003dc8:	20000018 	.word	0x20000018
 8003dcc:	20000010 	.word	0x20000010

08003dd0 <HAL_RCC_DeInit>:
 8003dd0:	b510      	push	{r4, lr}
 8003dd2:	f7ff f951 	bl	8003078 <HAL_GetTick>
 8003dd6:	4604      	mov	r4, r0
 8003dd8:	483d      	ldr	r0, [pc, #244]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003dda:	6800      	ldr	r0, [r0, #0]
 8003ddc:	f040 0001 	orr.w	r0, r0, #1
 8003de0:	493b      	ldr	r1, [pc, #236]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003de2:	6008      	str	r0, [r1, #0]
 8003de4:	e006      	b.n	8003df4 <HAL_RCC_DeInit+0x24>
 8003de6:	f7ff f947 	bl	8003078 <HAL_GetTick>
 8003dea:	1b00      	subs	r0, r0, r4
 8003dec:	2802      	cmp	r0, #2
 8003dee:	d901      	bls.n	8003df4 <HAL_RCC_DeInit+0x24>
 8003df0:	2003      	movs	r0, #3
 8003df2:	bd10      	pop	{r4, pc}
 8003df4:	4836      	ldr	r0, [pc, #216]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003df6:	6800      	ldr	r0, [r0, #0]
 8003df8:	f000 0002 	and.w	r0, r0, #2
 8003dfc:	2800      	cmp	r0, #0
 8003dfe:	d0f2      	beq.n	8003de6 <HAL_RCC_DeInit+0x16>
 8003e00:	4833      	ldr	r0, [pc, #204]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e02:	6800      	ldr	r0, [r0, #0]
 8003e04:	f020 00f8 	bic.w	r0, r0, #248	@ 0xf8
 8003e08:	f040 0080 	orr.w	r0, r0, #128	@ 0x80
 8003e0c:	4930      	ldr	r1, [pc, #192]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e0e:	6008      	str	r0, [r1, #0]
 8003e10:	f7ff f932 	bl	8003078 <HAL_GetTick>
 8003e14:	4604      	mov	r4, r0
 8003e16:	2000      	movs	r0, #0
 8003e18:	492d      	ldr	r1, [pc, #180]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e1a:	6048      	str	r0, [r1, #4]
 8003e1c:	e008      	b.n	8003e30 <HAL_RCC_DeInit+0x60>
 8003e1e:	f7ff f92b 	bl	8003078 <HAL_GetTick>
 8003e22:	1b00      	subs	r0, r0, r4
 8003e24:	f241 3188 	movw	r1, #5000	@ 0x1388
 8003e28:	4288      	cmp	r0, r1
 8003e2a:	d901      	bls.n	8003e30 <HAL_RCC_DeInit+0x60>
 8003e2c:	2003      	movs	r0, #3
 8003e2e:	e7e0      	b.n	8003df2 <HAL_RCC_DeInit+0x22>
 8003e30:	4827      	ldr	r0, [pc, #156]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e32:	6840      	ldr	r0, [r0, #4]
 8003e34:	f000 000c 	and.w	r0, r0, #12
 8003e38:	2800      	cmp	r0, #0
 8003e3a:	d1f0      	bne.n	8003e1e <HAL_RCC_DeInit+0x4e>
 8003e3c:	4825      	ldr	r0, [pc, #148]	@ (8003ed4 <HAL_RCC_DeInit+0x104>)
 8003e3e:	4926      	ldr	r1, [pc, #152]	@ (8003ed8 <HAL_RCC_DeInit+0x108>)
 8003e40:	6008      	str	r0, [r1, #0]
 8003e42:	4826      	ldr	r0, [pc, #152]	@ (8003edc <HAL_RCC_DeInit+0x10c>)
 8003e44:	6800      	ldr	r0, [r0, #0]
 8003e46:	f7ff f9dd 	bl	8003204 <HAL_InitTick>
 8003e4a:	b108      	cbz	r0, 8003e50 <HAL_RCC_DeInit+0x80>
 8003e4c:	2001      	movs	r0, #1
 8003e4e:	e7d0      	b.n	8003df2 <HAL_RCC_DeInit+0x22>
 8003e50:	f7ff f912 	bl	8003078 <HAL_GetTick>
 8003e54:	4604      	mov	r4, r0
 8003e56:	481e      	ldr	r0, [pc, #120]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e58:	6800      	ldr	r0, [r0, #0]
 8003e5a:	f020 7080 	bic.w	r0, r0, #16777216	@ 0x1000000
 8003e5e:	491c      	ldr	r1, [pc, #112]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e60:	6008      	str	r0, [r1, #0]
 8003e62:	e006      	b.n	8003e72 <HAL_RCC_DeInit+0xa2>
 8003e64:	f7ff f908 	bl	8003078 <HAL_GetTick>
 8003e68:	1b00      	subs	r0, r0, r4
 8003e6a:	2802      	cmp	r0, #2
 8003e6c:	d901      	bls.n	8003e72 <HAL_RCC_DeInit+0xa2>
 8003e6e:	2003      	movs	r0, #3
 8003e70:	e7bf      	b.n	8003df2 <HAL_RCC_DeInit+0x22>
 8003e72:	4817      	ldr	r0, [pc, #92]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e74:	6800      	ldr	r0, [r0, #0]
 8003e76:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 8003e7a:	2800      	cmp	r0, #0
 8003e7c:	d1f2      	bne.n	8003e64 <HAL_RCC_DeInit+0x94>
 8003e7e:	4914      	ldr	r1, [pc, #80]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e80:	6048      	str	r0, [r1, #4]
 8003e82:	f7ff f8f9 	bl	8003078 <HAL_GetTick>
 8003e86:	4604      	mov	r4, r0
 8003e88:	4811      	ldr	r0, [pc, #68]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e8a:	6800      	ldr	r0, [r0, #0]
 8003e8c:	f420 2010 	bic.w	r0, r0, #589824	@ 0x90000
 8003e90:	490f      	ldr	r1, [pc, #60]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003e92:	6008      	str	r0, [r1, #0]
 8003e94:	e006      	b.n	8003ea4 <HAL_RCC_DeInit+0xd4>
 8003e96:	f7ff f8ef 	bl	8003078 <HAL_GetTick>
 8003e9a:	1b00      	subs	r0, r0, r4
 8003e9c:	2864      	cmp	r0, #100	@ 0x64
 8003e9e:	d901      	bls.n	8003ea4 <HAL_RCC_DeInit+0xd4>
 8003ea0:	2003      	movs	r0, #3
 8003ea2:	e7a6      	b.n	8003df2 <HAL_RCC_DeInit+0x22>
 8003ea4:	480a      	ldr	r0, [pc, #40]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003ea6:	6800      	ldr	r0, [r0, #0]
 8003ea8:	f400 3000 	and.w	r0, r0, #131072	@ 0x20000
 8003eac:	2800      	cmp	r0, #0
 8003eae:	d1f2      	bne.n	8003e96 <HAL_RCC_DeInit+0xc6>
 8003eb0:	4807      	ldr	r0, [pc, #28]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003eb2:	6800      	ldr	r0, [r0, #0]
 8003eb4:	f420 2080 	bic.w	r0, r0, #262144	@ 0x40000
 8003eb8:	4905      	ldr	r1, [pc, #20]	@ (8003ed0 <HAL_RCC_DeInit+0x100>)
 8003eba:	6008      	str	r0, [r1, #0]
 8003ebc:	4608      	mov	r0, r1
 8003ebe:	6a40      	ldr	r0, [r0, #36]	@ 0x24
 8003ec0:	f040 7080 	orr.w	r0, r0, #16777216	@ 0x1000000
 8003ec4:	6248      	str	r0, [r1, #36]	@ 0x24
 8003ec6:	2000      	movs	r0, #0
 8003ec8:	6088      	str	r0, [r1, #8]
 8003eca:	bf00      	nop
 8003ecc:	e791      	b.n	8003df2 <HAL_RCC_DeInit+0x22>
 8003ece:	0000      	.short	0x0000
 8003ed0:	40021000 	.word	0x40021000
 8003ed4:	007a1200 	.word	0x007a1200
 8003ed8:	20000018 	.word	0x20000018
 8003edc:	20000010 	.word	0x20000010

08003ee0 <HAL_RCC_DisableCSS>:
 8003ee0:	2000      	movs	r0, #0
 8003ee2:	4901      	ldr	r1, [pc, #4]	@ (8003ee8 <HAL_RCC_DisableCSS+0x8>)
 8003ee4:	64c8      	str	r0, [r1, #76]	@ 0x4c
 8003ee6:	4770      	bx	lr
 8003ee8:	42420000 	.word	0x42420000

08003eec <HAL_RCC_EnableCSS>:
 8003eec:	2001      	movs	r0, #1
 8003eee:	4901      	ldr	r1, [pc, #4]	@ (8003ef4 <HAL_RCC_EnableCSS+0x8>)
 8003ef0:	64c8      	str	r0, [r1, #76]	@ 0x4c
 8003ef2:	4770      	bx	lr
 8003ef4:	42420000 	.word	0x42420000

08003ef8 <HAL_RCC_GetClockConfig>:
 8003ef8:	220f      	movs	r2, #15
 8003efa:	6002      	str	r2, [r0, #0]
 8003efc:	4a0d      	ldr	r2, [pc, #52]	@ (8003f34 <HAL_RCC_GetClockConfig+0x3c>)
 8003efe:	6852      	ldr	r2, [r2, #4]
 8003f00:	f002 0203 	and.w	r2, r2, #3
 8003f04:	6042      	str	r2, [r0, #4]
 8003f06:	4a0b      	ldr	r2, [pc, #44]	@ (8003f34 <HAL_RCC_GetClockConfig+0x3c>)
 8003f08:	6852      	ldr	r2, [r2, #4]
 8003f0a:	f002 02f0 	and.w	r2, r2, #240	@ 0xf0
 8003f0e:	6082      	str	r2, [r0, #8]
 8003f10:	4a08      	ldr	r2, [pc, #32]	@ (8003f34 <HAL_RCC_GetClockConfig+0x3c>)
 8003f12:	6852      	ldr	r2, [r2, #4]
 8003f14:	f402 62e0 	and.w	r2, r2, #1792	@ 0x700
 8003f18:	60c2      	str	r2, [r0, #12]
 8003f1a:	4a06      	ldr	r2, [pc, #24]	@ (8003f34 <HAL_RCC_GetClockConfig+0x3c>)
 8003f1c:	6852      	ldr	r2, [r2, #4]
 8003f1e:	f402 5260 	and.w	r2, r2, #14336	@ 0x3800
 8003f22:	08d2      	lsrs	r2, r2, #3
 8003f24:	6102      	str	r2, [r0, #16]
 8003f26:	4a04      	ldr	r2, [pc, #16]	@ (8003f38 <HAL_RCC_GetClockConfig+0x40>)
 8003f28:	6812      	ldr	r2, [r2, #0]
 8003f2a:	f002 0207 	and.w	r2, r2, #7
 8003f2e:	600a      	str	r2, [r1, #0]
 8003f30:	4770      	bx	lr
 8003f32:	0000      	.short	0x0000
 8003f34:	40021000 	.word	0x40021000
 8003f38:	40022000 	.word	0x40022000

08003f3c <HAL_RCC_GetHCLKFreq>:
 8003f3c:	4801      	ldr	r0, [pc, #4]	@ (8003f44 <HAL_RCC_GetHCLKFreq+0x8>)
 8003f3e:	6800      	ldr	r0, [r0, #0]
 8003f40:	4770      	bx	lr
 8003f42:	0000      	.short	0x0000
 8003f44:	20000018 	.word	0x20000018

08003f48 <HAL_RCC_GetOscConfig>:
 8003f48:	210f      	movs	r1, #15
 8003f4a:	6001      	str	r1, [r0, #0]
 8003f4c:	492f      	ldr	r1, [pc, #188]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003f4e:	6809      	ldr	r1, [r1, #0]
 8003f50:	f401 2180 	and.w	r1, r1, #262144	@ 0x40000
 8003f54:	f5b1 2f80 	cmp.w	r1, #262144	@ 0x40000
 8003f58:	d103      	bne.n	8003f62 <HAL_RCC_GetOscConfig+0x1a>
 8003f5a:	f44f 21a0 	mov.w	r1, #327680	@ 0x50000
 8003f5e:	6041      	str	r1, [r0, #4]
 8003f60:	e00c      	b.n	8003f7c <HAL_RCC_GetOscConfig+0x34>
 8003f62:	492a      	ldr	r1, [pc, #168]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003f64:	6809      	ldr	r1, [r1, #0]
 8003f66:	f401 3180 	and.w	r1, r1, #65536	@ 0x10000
 8003f6a:	f5b1 3f80 	cmp.w	r1, #65536	@ 0x10000
 8003f6e:	d103      	bne.n	8003f78 <HAL_RCC_GetOscConfig+0x30>
 8003f70:	f44f 3180 	mov.w	r1, #65536	@ 0x10000
 8003f74:	6041      	str	r1, [r0, #4]
 8003f76:	e001      	b.n	8003f7c <HAL_RCC_GetOscConfig+0x34>
 8003f78:	2100      	movs	r1, #0
 8003f7a:	6041      	str	r1, [r0, #4]
 8003f7c:	4923      	ldr	r1, [pc, #140]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003f7e:	6849      	ldr	r1, [r1, #4]
 8003f80:	f401 3100 	and.w	r1, r1, #131072	@ 0x20000
 8003f84:	6081      	str	r1, [r0, #8]
 8003f86:	4921      	ldr	r1, [pc, #132]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003f88:	6809      	ldr	r1, [r1, #0]
 8003f8a:	f001 0101 	and.w	r1, r1, #1
 8003f8e:	b111      	cbz	r1, 8003f96 <HAL_RCC_GetOscConfig+0x4e>
 8003f90:	2101      	movs	r1, #1
 8003f92:	6101      	str	r1, [r0, #16]
 8003f94:	e001      	b.n	8003f9a <HAL_RCC_GetOscConfig+0x52>
 8003f96:	2100      	movs	r1, #0
 8003f98:	6101      	str	r1, [r0, #16]
 8003f9a:	491c      	ldr	r1, [pc, #112]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003f9c:	6809      	ldr	r1, [r1, #0]
 8003f9e:	f3c1 01c4 	ubfx	r1, r1, #3, #5
 8003fa2:	6141      	str	r1, [r0, #20]
 8003fa4:	4919      	ldr	r1, [pc, #100]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003fa6:	6a09      	ldr	r1, [r1, #32]
 8003fa8:	f001 0104 	and.w	r1, r1, #4
 8003fac:	2904      	cmp	r1, #4
 8003fae:	d102      	bne.n	8003fb6 <HAL_RCC_GetOscConfig+0x6e>
 8003fb0:	2105      	movs	r1, #5
 8003fb2:	60c1      	str	r1, [r0, #12]
 8003fb4:	e009      	b.n	8003fca <HAL_RCC_GetOscConfig+0x82>
 8003fb6:	4915      	ldr	r1, [pc, #84]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003fb8:	6a09      	ldr	r1, [r1, #32]
 8003fba:	f001 0101 	and.w	r1, r1, #1
 8003fbe:	b111      	cbz	r1, 8003fc6 <HAL_RCC_GetOscConfig+0x7e>
 8003fc0:	2101      	movs	r1, #1
 8003fc2:	60c1      	str	r1, [r0, #12]
 8003fc4:	e001      	b.n	8003fca <HAL_RCC_GetOscConfig+0x82>
 8003fc6:	2100      	movs	r1, #0
 8003fc8:	60c1      	str	r1, [r0, #12]
 8003fca:	4910      	ldr	r1, [pc, #64]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003fcc:	6a49      	ldr	r1, [r1, #36]	@ 0x24
 8003fce:	f001 0101 	and.w	r1, r1, #1
 8003fd2:	b111      	cbz	r1, 8003fda <HAL_RCC_GetOscConfig+0x92>
 8003fd4:	2101      	movs	r1, #1
 8003fd6:	6181      	str	r1, [r0, #24]
 8003fd8:	e001      	b.n	8003fde <HAL_RCC_GetOscConfig+0x96>
 8003fda:	2100      	movs	r1, #0
 8003fdc:	6181      	str	r1, [r0, #24]
 8003fde:	490b      	ldr	r1, [pc, #44]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003fe0:	6809      	ldr	r1, [r1, #0]
 8003fe2:	f001 7180 	and.w	r1, r1, #16777216	@ 0x1000000
 8003fe6:	f1b1 7f80 	cmp.w	r1, #16777216	@ 0x1000000
 8003fea:	d102      	bne.n	8003ff2 <HAL_RCC_GetOscConfig+0xaa>
 8003fec:	2102      	movs	r1, #2
 8003fee:	61c1      	str	r1, [r0, #28]
 8003ff0:	e001      	b.n	8003ff6 <HAL_RCC_GetOscConfig+0xae>
 8003ff2:	2101      	movs	r1, #1
 8003ff4:	61c1      	str	r1, [r0, #28]
 8003ff6:	4905      	ldr	r1, [pc, #20]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8003ff8:	6849      	ldr	r1, [r1, #4]
 8003ffa:	f401 3280 	and.w	r2, r1, #65536	@ 0x10000
 8003ffe:	6202      	str	r2, [r0, #32]
 8004000:	4902      	ldr	r1, [pc, #8]	@ (800400c <HAL_RCC_GetOscConfig+0xc4>)
 8004002:	6849      	ldr	r1, [r1, #4]
 8004004:	f401 1270 	and.w	r2, r1, #3932160	@ 0x3c0000
 8004008:	6242      	str	r2, [r0, #36]	@ 0x24
 800400a:	4770      	bx	lr
 800400c:	40021000 	.word	0x40021000

08004010 <HAL_RCC_GetPCLK1Freq>:
 8004010:	b500      	push	{lr}
 8004012:	f7ff ff93 	bl	8003f3c <HAL_RCC_GetHCLKFreq>
 8004016:	4904      	ldr	r1, [pc, #16]	@ (8004028 <HAL_RCC_GetPCLK1Freq+0x18>)
 8004018:	6849      	ldr	r1, [r1, #4]
 800401a:	f3c1 2102 	ubfx	r1, r1, #8, #3
 800401e:	4a03      	ldr	r2, [pc, #12]	@ (800402c <HAL_RCC_GetPCLK1Freq+0x1c>)
 8004020:	5c51      	ldrb	r1, [r2, r1]
 8004022:	40c8      	lsrs	r0, r1
 8004024:	bd00      	pop	{pc}
 8004026:	0000      	.short	0x0000
 8004028:	40021000 	.word	0x40021000
 800402c:	08006cb9 	.word	0x08006cb9

08004030 <HAL_RCC_GetPCLK2Freq>:
 8004030:	b500      	push	{lr}
 8004032:	f7ff ff83 	bl	8003f3c <HAL_RCC_GetHCLKFreq>
 8004036:	4904      	ldr	r1, [pc, #16]	@ (8004048 <HAL_RCC_GetPCLK2Freq+0x18>)
 8004038:	6849      	ldr	r1, [r1, #4]
 800403a:	f3c1 21c2 	ubfx	r1, r1, #11, #3
 800403e:	4a03      	ldr	r2, [pc, #12]	@ (800404c <HAL_RCC_GetPCLK2Freq+0x1c>)
 8004040:	5c51      	ldrb	r1, [r2, r1]
 8004042:	40c8      	lsrs	r0, r1
 8004044:	bd00      	pop	{pc}
 8004046:	0000      	.short	0x0000
 8004048:	40021000 	.word	0x40021000
 800404c:	08006cb9 	.word	0x08006cb9

08004050 <HAL_RCC_GetSysClockFreq>:
 8004050:	b570      	push	{r4, r5, r6, lr}
 8004052:	2100      	movs	r1, #0
 8004054:	2200      	movs	r2, #0
 8004056:	2400      	movs	r4, #0
 8004058:	2300      	movs	r3, #0
 800405a:	2000      	movs	r0, #0
 800405c:	4d13      	ldr	r5, [pc, #76]	@ (80040ac <HAL_RCC_GetSysClockFreq+0x5c>)
 800405e:	6869      	ldr	r1, [r5, #4]
 8004060:	f001 050c 	and.w	r5, r1, #12
 8004064:	b1f5      	cbz	r5, 80040a4 <HAL_RCC_GetSysClockFreq+0x54>
 8004066:	2d04      	cmp	r5, #4
 8004068:	d002      	beq.n	8004070 <HAL_RCC_GetSysClockFreq+0x20>
 800406a:	2d08      	cmp	r5, #8
 800406c:	d119      	bne.n	80040a2 <HAL_RCC_GetSysClockFreq+0x52>
 800406e:	e001      	b.n	8004074 <HAL_RCC_GetSysClockFreq+0x24>
 8004070:	480f      	ldr	r0, [pc, #60]	@ (80040b0 <HAL_RCC_GetSysClockFreq+0x60>)
 8004072:	e019      	b.n	80040a8 <HAL_RCC_GetSysClockFreq+0x58>
 8004074:	4d0f      	ldr	r5, [pc, #60]	@ (80040b4 <HAL_RCC_GetSysClockFreq+0x64>)
 8004076:	f3c1 4683 	ubfx	r6, r1, #18, #4
 800407a:	5dab      	ldrb	r3, [r5, r6]
 800407c:	f401 3580 	and.w	r5, r1, #65536	@ 0x10000
 8004080:	b155      	cbz	r5, 8004098 <HAL_RCC_GetSysClockFreq+0x48>
 8004082:	4d0a      	ldr	r5, [pc, #40]	@ (80040ac <HAL_RCC_GetSysClockFreq+0x5c>)
 8004084:	686d      	ldr	r5, [r5, #4]
 8004086:	f3c5 4540 	ubfx	r5, r5, #17, #1
 800408a:	4e0b      	ldr	r6, [pc, #44]	@ (80040b8 <HAL_RCC_GetSysClockFreq+0x68>)
 800408c:	5d72      	ldrb	r2, [r6, r5]
 800408e:	4d08      	ldr	r5, [pc, #32]	@ (80040b0 <HAL_RCC_GetSysClockFreq+0x60>)
 8004090:	435d      	muls	r5, r3
 8004092:	fbb5 f4f2 	udiv	r4, r5, r2
 8004096:	e002      	b.n	800409e <HAL_RCC_GetSysClockFreq+0x4e>
 8004098:	4d08      	ldr	r5, [pc, #32]	@ (80040bc <HAL_RCC_GetSysClockFreq+0x6c>)
 800409a:	fb03 f405 	mul.w	r4, r3, r5
 800409e:	4620      	mov	r0, r4
 80040a0:	e002      	b.n	80040a8 <HAL_RCC_GetSysClockFreq+0x58>
 80040a2:	bf00      	nop
 80040a4:	4802      	ldr	r0, [pc, #8]	@ (80040b0 <HAL_RCC_GetSysClockFreq+0x60>)
 80040a6:	bf00      	nop
 80040a8:	bf00      	nop
 80040aa:	bd70      	pop	{r4, r5, r6, pc}
 80040ac:	40021000 	.word	0x40021000
 80040b0:	007a1200 	.word	0x007a1200
 80040b4:	08006c85 	.word	0x08006c85
 80040b8:	08006c95 	.word	0x08006c95
 80040bc:	003d0900 	.word	0x003d0900

080040c0 <HAL_RCC_MCOConfig>:
 80040c0:	b570      	push	{r4, r5, r6, lr}
 80040c2:	b086      	sub	sp, #24
 80040c4:	4605      	mov	r5, r0
 80040c6:	460c      	mov	r4, r1
 80040c8:	4616      	mov	r6, r2
 80040ca:	2000      	movs	r0, #0
 80040cc:	9002      	str	r0, [sp, #8]
 80040ce:	9003      	str	r0, [sp, #12]
 80040d0:	9004      	str	r0, [sp, #16]
 80040d2:	9005      	str	r0, [sp, #20]
 80040d4:	2002      	movs	r0, #2
 80040d6:	9003      	str	r0, [sp, #12]
 80040d8:	2003      	movs	r0, #3
 80040da:	9005      	str	r0, [sp, #20]
 80040dc:	2000      	movs	r0, #0
 80040de:	9004      	str	r0, [sp, #16]
 80040e0:	f44f 7080 	mov.w	r0, #256	@ 0x100
 80040e4:	9002      	str	r0, [sp, #8]
 80040e6:	bf00      	nop
 80040e8:	480c      	ldr	r0, [pc, #48]	@ (800411c <HAL_RCC_MCOConfig+0x5c>)
 80040ea:	6980      	ldr	r0, [r0, #24]
 80040ec:	f040 0004 	orr.w	r0, r0, #4
 80040f0:	490a      	ldr	r1, [pc, #40]	@ (800411c <HAL_RCC_MCOConfig+0x5c>)
 80040f2:	6188      	str	r0, [r1, #24]
 80040f4:	4608      	mov	r0, r1
 80040f6:	6980      	ldr	r0, [r0, #24]
 80040f8:	f000 0004 	and.w	r0, r0, #4
 80040fc:	9001      	str	r0, [sp, #4]
 80040fe:	bf00      	nop
 8004100:	bf00      	nop
 8004102:	a902      	add	r1, sp, #8
 8004104:	4806      	ldr	r0, [pc, #24]	@ (8004120 <HAL_RCC_MCOConfig+0x60>)
 8004106:	f7fe fdd5 	bl	8002cb4 <HAL_GPIO_Init>
 800410a:	4804      	ldr	r0, [pc, #16]	@ (800411c <HAL_RCC_MCOConfig+0x5c>)
 800410c:	6840      	ldr	r0, [r0, #4]
 800410e:	f020 60e0 	bic.w	r0, r0, #117440512	@ 0x7000000
 8004112:	4320      	orrs	r0, r4
 8004114:	4901      	ldr	r1, [pc, #4]	@ (800411c <HAL_RCC_MCOConfig+0x5c>)
 8004116:	6048      	str	r0, [r1, #4]
 8004118:	b006      	add	sp, #24
 800411a:	bd70      	pop	{r4, r5, r6, pc}
 800411c:	40021000 	.word	0x40021000
 8004120:	40010800 	.word	0x40010800

08004124 <HAL_RCC_NMI_IRQHandler>:
 8004124:	b510      	push	{r4, lr}
 8004126:	4806      	ldr	r0, [pc, #24]	@ (8004140 <HAL_RCC_NMI_IRQHandler+0x1c>)
 8004128:	6880      	ldr	r0, [r0, #8]
 800412a:	f000 0080 	and.w	r0, r0, #128	@ 0x80
 800412e:	2880      	cmp	r0, #128	@ 0x80
 8004130:	d104      	bne.n	800413c <HAL_RCC_NMI_IRQHandler+0x18>
 8004132:	f7ff fd85 	bl	8003c40 <HAL_RCC_CSSCallback>
 8004136:	2080      	movs	r0, #128	@ 0x80
 8004138:	4901      	ldr	r1, [pc, #4]	@ (8004140 <HAL_RCC_NMI_IRQHandler+0x1c>)
 800413a:	7288      	strb	r0, [r1, #10]
 800413c:	bd10      	pop	{r4, pc}
 800413e:	0000      	.short	0x0000
 8004140:	40021000 	.word	0x40021000

08004144 <HAL_RCC_OscConfig>:
 8004144:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8004146:	4604      	mov	r4, r0
 8004148:	b90c      	cbnz	r4, 800414e <HAL_RCC_OscConfig+0xa>
 800414a:	2001      	movs	r0, #1
 800414c:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 800414e:	7820      	ldrb	r0, [r4, #0]
 8004150:	f000 0001 	and.w	r0, r0, #1
 8004154:	2800      	cmp	r0, #0
 8004156:	d078      	beq.n	800424a <HAL_RCC_OscConfig+0x106>
 8004158:	48f8      	ldr	r0, [pc, #992]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 800415a:	6840      	ldr	r0, [r0, #4]
 800415c:	f000 000c 	and.w	r0, r0, #12
 8004160:	2804      	cmp	r0, #4
 8004162:	d00c      	beq.n	800417e <HAL_RCC_OscConfig+0x3a>
 8004164:	48f5      	ldr	r0, [pc, #980]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004166:	6840      	ldr	r0, [r0, #4]
 8004168:	f000 000c 	and.w	r0, r0, #12
 800416c:	2808      	cmp	r0, #8
 800416e:	d111      	bne.n	8004194 <HAL_RCC_OscConfig+0x50>
 8004170:	48f2      	ldr	r0, [pc, #968]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004172:	6840      	ldr	r0, [r0, #4]
 8004174:	f400 3080 	and.w	r0, r0, #65536	@ 0x10000
 8004178:	f5b0 3f80 	cmp.w	r0, #65536	@ 0x10000
 800417c:	d10a      	bne.n	8004194 <HAL_RCC_OscConfig+0x50>
 800417e:	48ef      	ldr	r0, [pc, #956]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004180:	6800      	ldr	r0, [r0, #0]
 8004182:	f400 3000 	and.w	r0, r0, #131072	@ 0x20000
 8004186:	2800      	cmp	r0, #0
 8004188:	d05f      	beq.n	800424a <HAL_RCC_OscConfig+0x106>
 800418a:	6860      	ldr	r0, [r4, #4]
 800418c:	2800      	cmp	r0, #0
 800418e:	d15c      	bne.n	800424a <HAL_RCC_OscConfig+0x106>
 8004190:	2001      	movs	r0, #1
 8004192:	e7db      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 8004194:	bf00      	nop
 8004196:	6860      	ldr	r0, [r4, #4]
 8004198:	f5b0 3f80 	cmp.w	r0, #65536	@ 0x10000
 800419c:	d106      	bne.n	80041ac <HAL_RCC_OscConfig+0x68>
 800419e:	48e7      	ldr	r0, [pc, #924]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041a0:	6800      	ldr	r0, [r0, #0]
 80041a2:	f440 3080 	orr.w	r0, r0, #65536	@ 0x10000
 80041a6:	49e5      	ldr	r1, [pc, #916]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041a8:	6008      	str	r0, [r1, #0]
 80041aa:	e028      	b.n	80041fe <HAL_RCC_OscConfig+0xba>
 80041ac:	6860      	ldr	r0, [r4, #4]
 80041ae:	b958      	cbnz	r0, 80041c8 <HAL_RCC_OscConfig+0x84>
 80041b0:	48e2      	ldr	r0, [pc, #904]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041b2:	6800      	ldr	r0, [r0, #0]
 80041b4:	f420 3080 	bic.w	r0, r0, #65536	@ 0x10000
 80041b8:	49e0      	ldr	r1, [pc, #896]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041ba:	6008      	str	r0, [r1, #0]
 80041bc:	4608      	mov	r0, r1
 80041be:	6800      	ldr	r0, [r0, #0]
 80041c0:	f420 2080 	bic.w	r0, r0, #262144	@ 0x40000
 80041c4:	6008      	str	r0, [r1, #0]
 80041c6:	e01a      	b.n	80041fe <HAL_RCC_OscConfig+0xba>
 80041c8:	6860      	ldr	r0, [r4, #4]
 80041ca:	f5b0 2fa0 	cmp.w	r0, #327680	@ 0x50000
 80041ce:	d10b      	bne.n	80041e8 <HAL_RCC_OscConfig+0xa4>
 80041d0:	48da      	ldr	r0, [pc, #872]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041d2:	6800      	ldr	r0, [r0, #0]
 80041d4:	f440 2080 	orr.w	r0, r0, #262144	@ 0x40000
 80041d8:	49d8      	ldr	r1, [pc, #864]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041da:	6008      	str	r0, [r1, #0]
 80041dc:	4608      	mov	r0, r1
 80041de:	6800      	ldr	r0, [r0, #0]
 80041e0:	f440 3080 	orr.w	r0, r0, #65536	@ 0x10000
 80041e4:	6008      	str	r0, [r1, #0]
 80041e6:	e00a      	b.n	80041fe <HAL_RCC_OscConfig+0xba>
 80041e8:	48d4      	ldr	r0, [pc, #848]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041ea:	6800      	ldr	r0, [r0, #0]
 80041ec:	f420 3080 	bic.w	r0, r0, #65536	@ 0x10000
 80041f0:	49d2      	ldr	r1, [pc, #840]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80041f2:	6008      	str	r0, [r1, #0]
 80041f4:	4608      	mov	r0, r1
 80041f6:	6800      	ldr	r0, [r0, #0]
 80041f8:	f420 2080 	bic.w	r0, r0, #262144	@ 0x40000
 80041fc:	6008      	str	r0, [r1, #0]
 80041fe:	bf00      	nop
 8004200:	6860      	ldr	r0, [r4, #4]
 8004202:	b188      	cbz	r0, 8004228 <HAL_RCC_OscConfig+0xe4>
 8004204:	f7fe ff38 	bl	8003078 <HAL_GetTick>
 8004208:	4605      	mov	r5, r0
 800420a:	e006      	b.n	800421a <HAL_RCC_OscConfig+0xd6>
 800420c:	f7fe ff34 	bl	8003078 <HAL_GetTick>
 8004210:	1b40      	subs	r0, r0, r5
 8004212:	2864      	cmp	r0, #100	@ 0x64
 8004214:	d901      	bls.n	800421a <HAL_RCC_OscConfig+0xd6>
 8004216:	2003      	movs	r0, #3
 8004218:	e798      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800421a:	48c8      	ldr	r0, [pc, #800]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 800421c:	6800      	ldr	r0, [r0, #0]
 800421e:	f400 3000 	and.w	r0, r0, #131072	@ 0x20000
 8004222:	2800      	cmp	r0, #0
 8004224:	d0f2      	beq.n	800420c <HAL_RCC_OscConfig+0xc8>
 8004226:	e010      	b.n	800424a <HAL_RCC_OscConfig+0x106>
 8004228:	f7fe ff26 	bl	8003078 <HAL_GetTick>
 800422c:	4605      	mov	r5, r0
 800422e:	e006      	b.n	800423e <HAL_RCC_OscConfig+0xfa>
 8004230:	f7fe ff22 	bl	8003078 <HAL_GetTick>
 8004234:	1b40      	subs	r0, r0, r5
 8004236:	2864      	cmp	r0, #100	@ 0x64
 8004238:	d901      	bls.n	800423e <HAL_RCC_OscConfig+0xfa>
 800423a:	2003      	movs	r0, #3
 800423c:	e786      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800423e:	48bf      	ldr	r0, [pc, #764]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004240:	6800      	ldr	r0, [r0, #0]
 8004242:	f400 3000 	and.w	r0, r0, #131072	@ 0x20000
 8004246:	2800      	cmp	r0, #0
 8004248:	d1f2      	bne.n	8004230 <HAL_RCC_OscConfig+0xec>
 800424a:	7820      	ldrb	r0, [r4, #0]
 800424c:	f000 0002 	and.w	r0, r0, #2
 8004250:	2802      	cmp	r0, #2
 8004252:	d157      	bne.n	8004304 <HAL_RCC_OscConfig+0x1c0>
 8004254:	48b9      	ldr	r0, [pc, #740]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004256:	6840      	ldr	r0, [r0, #4]
 8004258:	f000 000c 	and.w	r0, r0, #12
 800425c:	b150      	cbz	r0, 8004274 <HAL_RCC_OscConfig+0x130>
 800425e:	48b7      	ldr	r0, [pc, #732]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004260:	6840      	ldr	r0, [r0, #4]
 8004262:	f000 000c 	and.w	r0, r0, #12
 8004266:	2808      	cmp	r0, #8
 8004268:	d118      	bne.n	800429c <HAL_RCC_OscConfig+0x158>
 800426a:	48b4      	ldr	r0, [pc, #720]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 800426c:	6840      	ldr	r0, [r0, #4]
 800426e:	f400 3080 	and.w	r0, r0, #65536	@ 0x10000
 8004272:	b998      	cbnz	r0, 800429c <HAL_RCC_OscConfig+0x158>
 8004274:	48b1      	ldr	r0, [pc, #708]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004276:	6800      	ldr	r0, [r0, #0]
 8004278:	f000 0002 	and.w	r0, r0, #2
 800427c:	b120      	cbz	r0, 8004288 <HAL_RCC_OscConfig+0x144>
 800427e:	6920      	ldr	r0, [r4, #16]
 8004280:	2801      	cmp	r0, #1
 8004282:	d001      	beq.n	8004288 <HAL_RCC_OscConfig+0x144>
 8004284:	2001      	movs	r0, #1
 8004286:	e761      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 8004288:	48ac      	ldr	r0, [pc, #688]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 800428a:	6800      	ldr	r0, [r0, #0]
 800428c:	f020 00f8 	bic.w	r0, r0, #248	@ 0xf8
 8004290:	6961      	ldr	r1, [r4, #20]
 8004292:	ea40 00c1 	orr.w	r0, r0, r1, lsl #3
 8004296:	49a9      	ldr	r1, [pc, #676]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004298:	6008      	str	r0, [r1, #0]
 800429a:	e033      	b.n	8004304 <HAL_RCC_OscConfig+0x1c0>
 800429c:	6920      	ldr	r0, [r4, #16]
 800429e:	b1e8      	cbz	r0, 80042dc <HAL_RCC_OscConfig+0x198>
 80042a0:	2001      	movs	r0, #1
 80042a2:	49a7      	ldr	r1, [pc, #668]	@ (8004540 <HAL_RCC_OscConfig+0x3fc>)
 80042a4:	6008      	str	r0, [r1, #0]
 80042a6:	f7fe fee7 	bl	8003078 <HAL_GetTick>
 80042aa:	4605      	mov	r5, r0
 80042ac:	e006      	b.n	80042bc <HAL_RCC_OscConfig+0x178>
 80042ae:	f7fe fee3 	bl	8003078 <HAL_GetTick>
 80042b2:	1b40      	subs	r0, r0, r5
 80042b4:	2802      	cmp	r0, #2
 80042b6:	d901      	bls.n	80042bc <HAL_RCC_OscConfig+0x178>
 80042b8:	2003      	movs	r0, #3
 80042ba:	e747      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 80042bc:	489f      	ldr	r0, [pc, #636]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80042be:	6800      	ldr	r0, [r0, #0]
 80042c0:	f000 0002 	and.w	r0, r0, #2
 80042c4:	2800      	cmp	r0, #0
 80042c6:	d0f2      	beq.n	80042ae <HAL_RCC_OscConfig+0x16a>
 80042c8:	489c      	ldr	r0, [pc, #624]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80042ca:	6800      	ldr	r0, [r0, #0]
 80042cc:	f020 00f8 	bic.w	r0, r0, #248	@ 0xf8
 80042d0:	6961      	ldr	r1, [r4, #20]
 80042d2:	ea40 00c1 	orr.w	r0, r0, r1, lsl #3
 80042d6:	4999      	ldr	r1, [pc, #612]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80042d8:	6008      	str	r0, [r1, #0]
 80042da:	e013      	b.n	8004304 <HAL_RCC_OscConfig+0x1c0>
 80042dc:	2000      	movs	r0, #0
 80042de:	4998      	ldr	r1, [pc, #608]	@ (8004540 <HAL_RCC_OscConfig+0x3fc>)
 80042e0:	6008      	str	r0, [r1, #0]
 80042e2:	f7fe fec9 	bl	8003078 <HAL_GetTick>
 80042e6:	4605      	mov	r5, r0
 80042e8:	e006      	b.n	80042f8 <HAL_RCC_OscConfig+0x1b4>
 80042ea:	f7fe fec5 	bl	8003078 <HAL_GetTick>
 80042ee:	1b40      	subs	r0, r0, r5
 80042f0:	2802      	cmp	r0, #2
 80042f2:	d901      	bls.n	80042f8 <HAL_RCC_OscConfig+0x1b4>
 80042f4:	2003      	movs	r0, #3
 80042f6:	e729      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 80042f8:	4890      	ldr	r0, [pc, #576]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80042fa:	6800      	ldr	r0, [r0, #0]
 80042fc:	f000 0002 	and.w	r0, r0, #2
 8004300:	2800      	cmp	r0, #0
 8004302:	d1f2      	bne.n	80042ea <HAL_RCC_OscConfig+0x1a6>
 8004304:	7820      	ldrb	r0, [r4, #0]
 8004306:	f000 0008 	and.w	r0, r0, #8
 800430a:	2808      	cmp	r0, #8
 800430c:	d12d      	bne.n	800436a <HAL_RCC_OscConfig+0x226>
 800430e:	69a0      	ldr	r0, [r4, #24]
 8004310:	b1b8      	cbz	r0, 8004342 <HAL_RCC_OscConfig+0x1fe>
 8004312:	2001      	movs	r0, #1
 8004314:	498b      	ldr	r1, [pc, #556]	@ (8004544 <HAL_RCC_OscConfig+0x400>)
 8004316:	6008      	str	r0, [r1, #0]
 8004318:	f7fe feae 	bl	8003078 <HAL_GetTick>
 800431c:	4605      	mov	r5, r0
 800431e:	e006      	b.n	800432e <HAL_RCC_OscConfig+0x1ea>
 8004320:	f7fe feaa 	bl	8003078 <HAL_GetTick>
 8004324:	1b40      	subs	r0, r0, r5
 8004326:	2802      	cmp	r0, #2
 8004328:	d901      	bls.n	800432e <HAL_RCC_OscConfig+0x1ea>
 800432a:	2003      	movs	r0, #3
 800432c:	e70e      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800432e:	4883      	ldr	r0, [pc, #524]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004330:	6a40      	ldr	r0, [r0, #36]	@ 0x24
 8004332:	f000 0002 	and.w	r0, r0, #2
 8004336:	2800      	cmp	r0, #0
 8004338:	d0f2      	beq.n	8004320 <HAL_RCC_OscConfig+0x1dc>
 800433a:	2001      	movs	r0, #1
 800433c:	f001 f9ec 	bl	8005718 <RCC_Delay>
 8004340:	e013      	b.n	800436a <HAL_RCC_OscConfig+0x226>
 8004342:	2000      	movs	r0, #0
 8004344:	497f      	ldr	r1, [pc, #508]	@ (8004544 <HAL_RCC_OscConfig+0x400>)
 8004346:	6008      	str	r0, [r1, #0]
 8004348:	f7fe fe96 	bl	8003078 <HAL_GetTick>
 800434c:	4605      	mov	r5, r0
 800434e:	e006      	b.n	800435e <HAL_RCC_OscConfig+0x21a>
 8004350:	f7fe fe92 	bl	8003078 <HAL_GetTick>
 8004354:	1b40      	subs	r0, r0, r5
 8004356:	2802      	cmp	r0, #2
 8004358:	d901      	bls.n	800435e <HAL_RCC_OscConfig+0x21a>
 800435a:	2003      	movs	r0, #3
 800435c:	e6f6      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800435e:	4877      	ldr	r0, [pc, #476]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004360:	6a40      	ldr	r0, [r0, #36]	@ 0x24
 8004362:	f000 0002 	and.w	r0, r0, #2
 8004366:	2800      	cmp	r0, #0
 8004368:	d1f2      	bne.n	8004350 <HAL_RCC_OscConfig+0x20c>
 800436a:	7820      	ldrb	r0, [r4, #0]
 800436c:	f000 0004 	and.w	r0, r0, #4
 8004370:	2804      	cmp	r0, #4
 8004372:	d173      	bne.n	800445c <HAL_RCC_OscConfig+0x318>
 8004374:	2700      	movs	r7, #0
 8004376:	4871      	ldr	r0, [pc, #452]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004378:	69c0      	ldr	r0, [r0, #28]
 800437a:	f000 5080 	and.w	r0, r0, #268435456	@ 0x10000000
 800437e:	b970      	cbnz	r0, 800439e <HAL_RCC_OscConfig+0x25a>
 8004380:	bf00      	nop
 8004382:	486e      	ldr	r0, [pc, #440]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004384:	69c0      	ldr	r0, [r0, #28]
 8004386:	f040 5080 	orr.w	r0, r0, #268435456	@ 0x10000000
 800438a:	496c      	ldr	r1, [pc, #432]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 800438c:	61c8      	str	r0, [r1, #28]
 800438e:	4608      	mov	r0, r1
 8004390:	69c0      	ldr	r0, [r0, #28]
 8004392:	f000 5080 	and.w	r0, r0, #268435456	@ 0x10000000
 8004396:	9000      	str	r0, [sp, #0]
 8004398:	bf00      	nop
 800439a:	bf00      	nop
 800439c:	2701      	movs	r7, #1
 800439e:	486a      	ldr	r0, [pc, #424]	@ (8004548 <HAL_RCC_OscConfig+0x404>)
 80043a0:	6800      	ldr	r0, [r0, #0]
 80043a2:	f400 7080 	and.w	r0, r0, #256	@ 0x100
 80043a6:	b9b0      	cbnz	r0, 80043d6 <HAL_RCC_OscConfig+0x292>
 80043a8:	4867      	ldr	r0, [pc, #412]	@ (8004548 <HAL_RCC_OscConfig+0x404>)
 80043aa:	6800      	ldr	r0, [r0, #0]
 80043ac:	f440 7080 	orr.w	r0, r0, #256	@ 0x100
 80043b0:	4965      	ldr	r1, [pc, #404]	@ (8004548 <HAL_RCC_OscConfig+0x404>)
 80043b2:	6008      	str	r0, [r1, #0]
 80043b4:	f7fe fe60 	bl	8003078 <HAL_GetTick>
 80043b8:	4605      	mov	r5, r0
 80043ba:	e006      	b.n	80043ca <HAL_RCC_OscConfig+0x286>
 80043bc:	f7fe fe5c 	bl	8003078 <HAL_GetTick>
 80043c0:	1b40      	subs	r0, r0, r5
 80043c2:	2864      	cmp	r0, #100	@ 0x64
 80043c4:	d901      	bls.n	80043ca <HAL_RCC_OscConfig+0x286>
 80043c6:	2003      	movs	r0, #3
 80043c8:	e6c0      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 80043ca:	485f      	ldr	r0, [pc, #380]	@ (8004548 <HAL_RCC_OscConfig+0x404>)
 80043cc:	6800      	ldr	r0, [r0, #0]
 80043ce:	f400 7080 	and.w	r0, r0, #256	@ 0x100
 80043d2:	2800      	cmp	r0, #0
 80043d4:	d0f2      	beq.n	80043bc <HAL_RCC_OscConfig+0x278>
 80043d6:	bf00      	nop
 80043d8:	68e0      	ldr	r0, [r4, #12]
 80043da:	2801      	cmp	r0, #1
 80043dc:	d106      	bne.n	80043ec <HAL_RCC_OscConfig+0x2a8>
 80043de:	4857      	ldr	r0, [pc, #348]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80043e0:	6a00      	ldr	r0, [r0, #32]
 80043e2:	f040 0001 	orr.w	r0, r0, #1
 80043e6:	4955      	ldr	r1, [pc, #340]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80043e8:	6208      	str	r0, [r1, #32]
 80043ea:	e027      	b.n	800443c <HAL_RCC_OscConfig+0x2f8>
 80043ec:	68e0      	ldr	r0, [r4, #12]
 80043ee:	b958      	cbnz	r0, 8004408 <HAL_RCC_OscConfig+0x2c4>
 80043f0:	4852      	ldr	r0, [pc, #328]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80043f2:	6a00      	ldr	r0, [r0, #32]
 80043f4:	f020 0001 	bic.w	r0, r0, #1
 80043f8:	4950      	ldr	r1, [pc, #320]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80043fa:	6208      	str	r0, [r1, #32]
 80043fc:	4608      	mov	r0, r1
 80043fe:	6a00      	ldr	r0, [r0, #32]
 8004400:	f020 0004 	bic.w	r0, r0, #4
 8004404:	6208      	str	r0, [r1, #32]
 8004406:	e019      	b.n	800443c <HAL_RCC_OscConfig+0x2f8>
 8004408:	68e0      	ldr	r0, [r4, #12]
 800440a:	2805      	cmp	r0, #5
 800440c:	d10b      	bne.n	8004426 <HAL_RCC_OscConfig+0x2e2>
 800440e:	484b      	ldr	r0, [pc, #300]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004410:	6a00      	ldr	r0, [r0, #32]
 8004412:	f040 0004 	orr.w	r0, r0, #4
 8004416:	4949      	ldr	r1, [pc, #292]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004418:	6208      	str	r0, [r1, #32]
 800441a:	4608      	mov	r0, r1
 800441c:	6a00      	ldr	r0, [r0, #32]
 800441e:	f040 0001 	orr.w	r0, r0, #1
 8004422:	6208      	str	r0, [r1, #32]
 8004424:	e00a      	b.n	800443c <HAL_RCC_OscConfig+0x2f8>
 8004426:	4845      	ldr	r0, [pc, #276]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004428:	6a00      	ldr	r0, [r0, #32]
 800442a:	f020 0001 	bic.w	r0, r0, #1
 800442e:	4943      	ldr	r1, [pc, #268]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004430:	6208      	str	r0, [r1, #32]
 8004432:	4608      	mov	r0, r1
 8004434:	6a00      	ldr	r0, [r0, #32]
 8004436:	f020 0004 	bic.w	r0, r0, #4
 800443a:	6208      	str	r0, [r1, #32]
 800443c:	bf00      	nop
 800443e:	68e0      	ldr	r0, [r4, #12]
 8004440:	b1a0      	cbz	r0, 800446c <HAL_RCC_OscConfig+0x328>
 8004442:	f7fe fe19 	bl	8003078 <HAL_GetTick>
 8004446:	4605      	mov	r5, r0
 8004448:	e009      	b.n	800445e <HAL_RCC_OscConfig+0x31a>
 800444a:	f7fe fe15 	bl	8003078 <HAL_GetTick>
 800444e:	1b40      	subs	r0, r0, r5
 8004450:	f241 3188 	movw	r1, #5000	@ 0x1388
 8004454:	4288      	cmp	r0, r1
 8004456:	d902      	bls.n	800445e <HAL_RCC_OscConfig+0x31a>
 8004458:	2003      	movs	r0, #3
 800445a:	e677      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800445c:	e022      	b.n	80044a4 <HAL_RCC_OscConfig+0x360>
 800445e:	4837      	ldr	r0, [pc, #220]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004460:	6a00      	ldr	r0, [r0, #32]
 8004462:	f000 0002 	and.w	r0, r0, #2
 8004466:	2800      	cmp	r0, #0
 8004468:	d0ef      	beq.n	800444a <HAL_RCC_OscConfig+0x306>
 800446a:	e012      	b.n	8004492 <HAL_RCC_OscConfig+0x34e>
 800446c:	f7fe fe04 	bl	8003078 <HAL_GetTick>
 8004470:	4605      	mov	r5, r0
 8004472:	e008      	b.n	8004486 <HAL_RCC_OscConfig+0x342>
 8004474:	f7fe fe00 	bl	8003078 <HAL_GetTick>
 8004478:	1b40      	subs	r0, r0, r5
 800447a:	f241 3188 	movw	r1, #5000	@ 0x1388
 800447e:	4288      	cmp	r0, r1
 8004480:	d901      	bls.n	8004486 <HAL_RCC_OscConfig+0x342>
 8004482:	2003      	movs	r0, #3
 8004484:	e662      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 8004486:	482d      	ldr	r0, [pc, #180]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004488:	6a00      	ldr	r0, [r0, #32]
 800448a:	f000 0002 	and.w	r0, r0, #2
 800448e:	2800      	cmp	r0, #0
 8004490:	d1f0      	bne.n	8004474 <HAL_RCC_OscConfig+0x330>
 8004492:	2f01      	cmp	r7, #1
 8004494:	d105      	bne.n	80044a2 <HAL_RCC_OscConfig+0x35e>
 8004496:	4829      	ldr	r0, [pc, #164]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004498:	69c0      	ldr	r0, [r0, #28]
 800449a:	f020 5080 	bic.w	r0, r0, #268435456	@ 0x10000000
 800449e:	4927      	ldr	r1, [pc, #156]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80044a0:	61c8      	str	r0, [r1, #28]
 80044a2:	bf00      	nop
 80044a4:	69e0      	ldr	r0, [r4, #28]
 80044a6:	b3c8      	cbz	r0, 800451c <HAL_RCC_OscConfig+0x3d8>
 80044a8:	4824      	ldr	r0, [pc, #144]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80044aa:	6840      	ldr	r0, [r0, #4]
 80044ac:	f000 000c 	and.w	r0, r0, #12
 80044b0:	2808      	cmp	r0, #8
 80044b2:	d060      	beq.n	8004576 <HAL_RCC_OscConfig+0x432>
 80044b4:	69e0      	ldr	r0, [r4, #28]
 80044b6:	2802      	cmp	r0, #2
 80044b8:	d148      	bne.n	800454c <HAL_RCC_OscConfig+0x408>
 80044ba:	2000      	movs	r0, #0
 80044bc:	4920      	ldr	r1, [pc, #128]	@ (8004540 <HAL_RCC_OscConfig+0x3fc>)
 80044be:	6608      	str	r0, [r1, #96]	@ 0x60
 80044c0:	f7fe fdda 	bl	8003078 <HAL_GetTick>
 80044c4:	4605      	mov	r5, r0
 80044c6:	e006      	b.n	80044d6 <HAL_RCC_OscConfig+0x392>
 80044c8:	f7fe fdd6 	bl	8003078 <HAL_GetTick>
 80044cc:	1b40      	subs	r0, r0, r5
 80044ce:	2802      	cmp	r0, #2
 80044d0:	d901      	bls.n	80044d6 <HAL_RCC_OscConfig+0x392>
 80044d2:	2003      	movs	r0, #3
 80044d4:	e63a      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 80044d6:	4819      	ldr	r0, [pc, #100]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80044d8:	6800      	ldr	r0, [r0, #0]
 80044da:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 80044de:	2800      	cmp	r0, #0
 80044e0:	d1f2      	bne.n	80044c8 <HAL_RCC_OscConfig+0x384>
 80044e2:	6a20      	ldr	r0, [r4, #32]
 80044e4:	f5b0 3f80 	cmp.w	r0, #65536	@ 0x10000
 80044e8:	d107      	bne.n	80044fa <HAL_RCC_OscConfig+0x3b6>
 80044ea:	4814      	ldr	r0, [pc, #80]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80044ec:	6840      	ldr	r0, [r0, #4]
 80044ee:	f420 3000 	bic.w	r0, r0, #131072	@ 0x20000
 80044f2:	68a1      	ldr	r1, [r4, #8]
 80044f4:	4308      	orrs	r0, r1
 80044f6:	4911      	ldr	r1, [pc, #68]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 80044f8:	6048      	str	r0, [r1, #4]
 80044fa:	e9d4 0108 	ldrd	r0, r1, [r4, #32]
 80044fe:	4308      	orrs	r0, r1
 8004500:	490e      	ldr	r1, [pc, #56]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 8004502:	6849      	ldr	r1, [r1, #4]
 8004504:	f421 1174 	bic.w	r1, r1, #3997696	@ 0x3d0000
 8004508:	4308      	orrs	r0, r1
 800450a:	490c      	ldr	r1, [pc, #48]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 800450c:	6048      	str	r0, [r1, #4]
 800450e:	2001      	movs	r0, #1
 8004510:	490b      	ldr	r1, [pc, #44]	@ (8004540 <HAL_RCC_OscConfig+0x3fc>)
 8004512:	6608      	str	r0, [r1, #96]	@ 0x60
 8004514:	f7fe fdb0 	bl	8003078 <HAL_GetTick>
 8004518:	4605      	mov	r5, r0
 800451a:	e007      	b.n	800452c <HAL_RCC_OscConfig+0x3e8>
 800451c:	e03d      	b.n	800459a <HAL_RCC_OscConfig+0x456>
 800451e:	f7fe fdab 	bl	8003078 <HAL_GetTick>
 8004522:	1b40      	subs	r0, r0, r5
 8004524:	2802      	cmp	r0, #2
 8004526:	d901      	bls.n	800452c <HAL_RCC_OscConfig+0x3e8>
 8004528:	2003      	movs	r0, #3
 800452a:	e60f      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800452c:	4803      	ldr	r0, [pc, #12]	@ (800453c <HAL_RCC_OscConfig+0x3f8>)
 800452e:	6800      	ldr	r0, [r0, #0]
 8004530:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 8004534:	2800      	cmp	r0, #0
 8004536:	d0f2      	beq.n	800451e <HAL_RCC_OscConfig+0x3da>
 8004538:	e02f      	b.n	800459a <HAL_RCC_OscConfig+0x456>
 800453a:	0000      	.short	0x0000
 800453c:	40021000 	.word	0x40021000
 8004540:	42420000 	.word	0x42420000
 8004544:	42420480 	.word	0x42420480
 8004548:	40007000 	.word	0x40007000
 800454c:	2000      	movs	r0, #0
 800454e:	4914      	ldr	r1, [pc, #80]	@ (80045a0 <HAL_RCC_OscConfig+0x45c>)
 8004550:	6608      	str	r0, [r1, #96]	@ 0x60
 8004552:	f7fe fd91 	bl	8003078 <HAL_GetTick>
 8004556:	4605      	mov	r5, r0
 8004558:	e006      	b.n	8004568 <HAL_RCC_OscConfig+0x424>
 800455a:	f7fe fd8d 	bl	8003078 <HAL_GetTick>
 800455e:	1b40      	subs	r0, r0, r5
 8004560:	2802      	cmp	r0, #2
 8004562:	d901      	bls.n	8004568 <HAL_RCC_OscConfig+0x424>
 8004564:	2003      	movs	r0, #3
 8004566:	e5f1      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 8004568:	480e      	ldr	r0, [pc, #56]	@ (80045a4 <HAL_RCC_OscConfig+0x460>)
 800456a:	6800      	ldr	r0, [r0, #0]
 800456c:	f000 7000 	and.w	r0, r0, #33554432	@ 0x2000000
 8004570:	2800      	cmp	r0, #0
 8004572:	d1f2      	bne.n	800455a <HAL_RCC_OscConfig+0x416>
 8004574:	e011      	b.n	800459a <HAL_RCC_OscConfig+0x456>
 8004576:	69e0      	ldr	r0, [r4, #28]
 8004578:	2801      	cmp	r0, #1
 800457a:	d100      	bne.n	800457e <HAL_RCC_OscConfig+0x43a>
 800457c:	e5e6      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800457e:	4809      	ldr	r0, [pc, #36]	@ (80045a4 <HAL_RCC_OscConfig+0x460>)
 8004580:	6846      	ldr	r6, [r0, #4]
 8004582:	f406 3180 	and.w	r1, r6, #65536	@ 0x10000
 8004586:	6a20      	ldr	r0, [r4, #32]
 8004588:	4281      	cmp	r1, r0
 800458a:	d104      	bne.n	8004596 <HAL_RCC_OscConfig+0x452>
 800458c:	f406 1170 	and.w	r1, r6, #3932160	@ 0x3c0000
 8004590:	6a60      	ldr	r0, [r4, #36]	@ 0x24
 8004592:	4281      	cmp	r1, r0
 8004594:	d001      	beq.n	800459a <HAL_RCC_OscConfig+0x456>
 8004596:	2001      	movs	r0, #1
 8004598:	e5d8      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800459a:	2000      	movs	r0, #0
 800459c:	e5d6      	b.n	800414c <HAL_RCC_OscConfig+0x8>
 800459e:	0000      	.short	0x0000
 80045a0:	42420000 	.word	0x42420000
 80045a4:	40021000 	.word	0x40021000

080045a8 <HAL_ResumeTick>:
 80045a8:	f04f 20e0 	mov.w	r0, #3758153728	@ 0xe000e000
 80045ac:	6900      	ldr	r0, [r0, #16]
 80045ae:	f040 0002 	orr.w	r0, r0, #2
 80045b2:	f04f 21e0 	mov.w	r1, #3758153728	@ 0xe000e000
 80045b6:	6108      	str	r0, [r1, #16]
 80045b8:	4770      	bx	lr

080045ba <HAL_SYSTICK_CLKSourceConfig>:
 80045ba:	2804      	cmp	r0, #4
 80045bc:	d108      	bne.n	80045d0 <HAL_SYSTICK_CLKSourceConfig+0x16>
 80045be:	f04f 21e0 	mov.w	r1, #3758153728	@ 0xe000e000
 80045c2:	6909      	ldr	r1, [r1, #16]
 80045c4:	f041 0104 	orr.w	r1, r1, #4
 80045c8:	f04f 22e0 	mov.w	r2, #3758153728	@ 0xe000e000
 80045cc:	6111      	str	r1, [r2, #16]
 80045ce:	e007      	b.n	80045e0 <HAL_SYSTICK_CLKSourceConfig+0x26>
 80045d0:	f04f 21e0 	mov.w	r1, #3758153728	@ 0xe000e000
 80045d4:	6909      	ldr	r1, [r1, #16]
 80045d6:	f021 0104 	bic.w	r1, r1, #4
 80045da:	f04f 22e0 	mov.w	r2, #3758153728	@ 0xe000e000
 80045de:	6111      	str	r1, [r2, #16]
 80045e0:	4770      	bx	lr

080045e2 <HAL_SYSTICK_Callback>:
 80045e2:	4770      	bx	lr

080045e4 <HAL_SYSTICK_Config>:
 80045e4:	b570      	push	{r4, r5, r6, lr}
 80045e6:	4604      	mov	r4, r0
 80045e8:	4625      	mov	r5, r4
 80045ea:	1e68      	subs	r0, r5, #1
 80045ec:	f1b0 7f80 	cmp.w	r0, #16777216	@ 0x1000000
 80045f0:	d301      	bcc.n	80045f6 <HAL_SYSTICK_Config+0x12>
 80045f2:	2001      	movs	r0, #1
 80045f4:	e00f      	b.n	8004616 <HAL_SYSTICK_Config+0x32>
 80045f6:	1e68      	subs	r0, r5, #1
 80045f8:	f04f 21e0 	mov.w	r1, #3758153728	@ 0xe000e000
 80045fc:	6148      	str	r0, [r1, #20]
 80045fe:	210f      	movs	r1, #15
 8004600:	f04f 30ff 	mov.w	r0, #4294967295
 8004604:	f001 fcb4 	bl	8005f70 <__NVIC_SetPriority>
 8004608:	2000      	movs	r0, #0
 800460a:	f04f 21e0 	mov.w	r1, #3758153728	@ 0xe000e000
 800460e:	6188      	str	r0, [r1, #24]
 8004610:	2007      	movs	r0, #7
 8004612:	6108      	str	r0, [r1, #16]
 8004614:	2000      	movs	r0, #0
 8004616:	bd70      	pop	{r4, r5, r6, pc}

08004618 <HAL_SYSTICK_IRQHandler>:
 8004618:	b510      	push	{r4, lr}
 800461a:	f7ff ffe2 	bl	80045e2 <HAL_SYSTICK_Callback>
 800461e:	bd10      	pop	{r4, pc}

08004620 <HAL_SetTickFreq>:
 8004620:	b570      	push	{r4, r5, r6, lr}
 8004622:	4604      	mov	r4, r0
 8004624:	2500      	movs	r5, #0
 8004626:	4808      	ldr	r0, [pc, #32]	@ (8004648 <HAL_SetTickFreq+0x28>)
 8004628:	7800      	ldrb	r0, [r0, #0]
 800462a:	42a0      	cmp	r0, r4
 800462c:	d00a      	beq.n	8004644 <HAL_SetTickFreq+0x24>
 800462e:	4806      	ldr	r0, [pc, #24]	@ (8004648 <HAL_SetTickFreq+0x28>)
 8004630:	7806      	ldrb	r6, [r0, #0]
 8004632:	7004      	strb	r4, [r0, #0]
 8004634:	4805      	ldr	r0, [pc, #20]	@ (800464c <HAL_SetTickFreq+0x2c>)
 8004636:	6800      	ldr	r0, [r0, #0]
 8004638:	f7fe fde4 	bl	8003204 <HAL_InitTick>
 800463c:	4605      	mov	r5, r0
 800463e:	b10d      	cbz	r5, 8004644 <HAL_SetTickFreq+0x24>
 8004640:	4801      	ldr	r0, [pc, #4]	@ (8004648 <HAL_SetTickFreq+0x28>)
 8004642:	7006      	strb	r6, [r0, #0]
 8004644:	4628      	mov	r0, r5
 8004646:	bd70      	pop	{r4, r5, r6, pc}
 8004648:	20000014 	.word	0x20000014
 800464c:	20000010 	.word	0x20000010

08004650 <HAL_SuspendTick>:
 8004650:	f04f 20e0 	mov.w	r0, #3758153728	@ 0xe000e000
 8004654:	6900      	ldr	r0, [r0, #16]
 8004656:	f020 0002 	bic.w	r0, r0, #2
 800465a:	f04f 21e0 	mov.w	r1, #3758153728	@ 0xe000e000
 800465e:	6108      	str	r0, [r1, #16]
 8004660:	4770      	bx	lr

08004662 <HAL_UARTEx_GetRxEventType>:
 8004662:	4601      	mov	r1, r0
 8004664:	6b48      	ldr	r0, [r1, #52]	@ 0x34
 8004666:	4770      	bx	lr

08004668 <HAL_UARTEx_ReceiveToIdle>:
 8004668:	e92d 4ff8 	stmdb	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
 800466c:	4604      	mov	r4, r0
 800466e:	460f      	mov	r7, r1
 8004670:	4690      	mov	r8, r2
 8004672:	461d      	mov	r5, r3
 8004674:	f8dd a028 	ldr.w	sl, [sp, #40]	@ 0x28
 8004678:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 800467c:	2820      	cmp	r0, #32
 800467e:	d178      	bne.n	8004772 <HAL_UARTEx_ReceiveToIdle+0x10a>
 8004680:	b117      	cbz	r7, 8004688 <HAL_UARTEx_ReceiveToIdle+0x20>
 8004682:	f1b8 0f00 	cmp.w	r8, #0
 8004686:	d102      	bne.n	800468e <HAL_UARTEx_ReceiveToIdle+0x26>
 8004688:	2001      	movs	r0, #1
 800468a:	e8bd 8ff8 	ldmia.w	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, pc}
 800468e:	2000      	movs	r0, #0
 8004690:	6460      	str	r0, [r4, #68]	@ 0x44
 8004692:	2022      	movs	r0, #34	@ 0x22
 8004694:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8004698:	2001      	movs	r0, #1
 800469a:	6320      	str	r0, [r4, #48]	@ 0x30
 800469c:	2000      	movs	r0, #0
 800469e:	6360      	str	r0, [r4, #52]	@ 0x34
 80046a0:	f7fe fcea 	bl	8003078 <HAL_GetTick>
 80046a4:	4683      	mov	fp, r0
 80046a6:	f8a4 802c 	strh.w	r8, [r4, #44]	@ 0x2c
 80046aa:	f8a4 802e 	strh.w	r8, [r4, #46]	@ 0x2e
 80046ae:	68a0      	ldr	r0, [r4, #8]
 80046b0:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 80046b4:	d104      	bne.n	80046c0 <HAL_UARTEx_ReceiveToIdle+0x58>
 80046b6:	6920      	ldr	r0, [r4, #16]
 80046b8:	b910      	cbnz	r0, 80046c0 <HAL_UARTEx_ReceiveToIdle+0x58>
 80046ba:	2600      	movs	r6, #0
 80046bc:	46b9      	mov	r9, r7
 80046be:	e002      	b.n	80046c6 <HAL_UARTEx_ReceiveToIdle+0x5e>
 80046c0:	463e      	mov	r6, r7
 80046c2:	f04f 0900 	mov.w	r9, #0
 80046c6:	2000      	movs	r0, #0
 80046c8:	8028      	strh	r0, [r5, #0]
 80046ca:	e053      	b.n	8004774 <HAL_UARTEx_ReceiveToIdle+0x10c>
 80046cc:	6820      	ldr	r0, [r4, #0]
 80046ce:	6800      	ldr	r0, [r0, #0]
 80046d0:	f000 0010 	and.w	r0, r0, #16
 80046d4:	2810      	cmp	r0, #16
 80046d6:	d113      	bne.n	8004700 <HAL_UARTEx_ReceiveToIdle+0x98>
 80046d8:	bf00      	nop
 80046da:	2000      	movs	r0, #0
 80046dc:	9000      	str	r0, [sp, #0]
 80046de:	6820      	ldr	r0, [r4, #0]
 80046e0:	6800      	ldr	r0, [r0, #0]
 80046e2:	9000      	str	r0, [sp, #0]
 80046e4:	6820      	ldr	r0, [r4, #0]
 80046e6:	6840      	ldr	r0, [r0, #4]
 80046e8:	9000      	str	r0, [sp, #0]
 80046ea:	bf00      	nop
 80046ec:	bf00      	nop
 80046ee:	8828      	ldrh	r0, [r5, #0]
 80046f0:	b130      	cbz	r0, 8004700 <HAL_UARTEx_ReceiveToIdle+0x98>
 80046f2:	2002      	movs	r0, #2
 80046f4:	6360      	str	r0, [r4, #52]	@ 0x34
 80046f6:	2020      	movs	r0, #32
 80046f8:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 80046fc:	2000      	movs	r0, #0
 80046fe:	e7c4      	b.n	800468a <HAL_UARTEx_ReceiveToIdle+0x22>
 8004700:	6820      	ldr	r0, [r4, #0]
 8004702:	6800      	ldr	r0, [r0, #0]
 8004704:	f000 0020 	and.w	r0, r0, #32
 8004708:	2820      	cmp	r0, #32
 800470a:	d121      	bne.n	8004750 <HAL_UARTEx_ReceiveToIdle+0xe8>
 800470c:	b946      	cbnz	r6, 8004720 <HAL_UARTEx_ReceiveToIdle+0xb8>
 800470e:	6820      	ldr	r0, [r4, #0]
 8004710:	6840      	ldr	r0, [r0, #4]
 8004712:	f3c0 0008 	ubfx	r0, r0, #0, #9
 8004716:	f8a9 0000 	strh.w	r0, [r9]
 800471a:	f109 0902 	add.w	r9, r9, #2
 800471e:	e011      	b.n	8004744 <HAL_UARTEx_ReceiveToIdle+0xdc>
 8004720:	68a0      	ldr	r0, [r4, #8]
 8004722:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 8004726:	d003      	beq.n	8004730 <HAL_UARTEx_ReceiveToIdle+0xc8>
 8004728:	68a0      	ldr	r0, [r4, #8]
 800472a:	b928      	cbnz	r0, 8004738 <HAL_UARTEx_ReceiveToIdle+0xd0>
 800472c:	6920      	ldr	r0, [r4, #16]
 800472e:	b918      	cbnz	r0, 8004738 <HAL_UARTEx_ReceiveToIdle+0xd0>
 8004730:	6820      	ldr	r0, [r4, #0]
 8004732:	6840      	ldr	r0, [r0, #4]
 8004734:	7030      	strb	r0, [r6, #0]
 8004736:	e004      	b.n	8004742 <HAL_UARTEx_ReceiveToIdle+0xda>
 8004738:	6820      	ldr	r0, [r4, #0]
 800473a:	6840      	ldr	r0, [r0, #4]
 800473c:	f000 007f 	and.w	r0, r0, #127	@ 0x7f
 8004740:	7030      	strb	r0, [r6, #0]
 8004742:	1c76      	adds	r6, r6, #1
 8004744:	8828      	ldrh	r0, [r5, #0]
 8004746:	1c40      	adds	r0, r0, #1
 8004748:	8028      	strh	r0, [r5, #0]
 800474a:	8de0      	ldrh	r0, [r4, #46]	@ 0x2e
 800474c:	1e40      	subs	r0, r0, #1
 800474e:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8004750:	f10a 0001 	add.w	r0, sl, #1
 8004754:	b170      	cbz	r0, 8004774 <HAL_UARTEx_ReceiveToIdle+0x10c>
 8004756:	f7fe fc8f 	bl	8003078 <HAL_GetTick>
 800475a:	eba0 000b 	sub.w	r0, r0, fp
 800475e:	4550      	cmp	r0, sl
 8004760:	d802      	bhi.n	8004768 <HAL_UARTEx_ReceiveToIdle+0x100>
 8004762:	f1ba 0f00 	cmp.w	sl, #0
 8004766:	d105      	bne.n	8004774 <HAL_UARTEx_ReceiveToIdle+0x10c>
 8004768:	2020      	movs	r0, #32
 800476a:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 800476e:	2003      	movs	r0, #3
 8004770:	e78b      	b.n	800468a <HAL_UARTEx_ReceiveToIdle+0x22>
 8004772:	e00b      	b.n	800478c <HAL_UARTEx_ReceiveToIdle+0x124>
 8004774:	8de0      	ldrh	r0, [r4, #46]	@ 0x2e
 8004776:	2800      	cmp	r0, #0
 8004778:	d1a8      	bne.n	80046cc <HAL_UARTEx_ReceiveToIdle+0x64>
 800477a:	8da0      	ldrh	r0, [r4, #44]	@ 0x2c
 800477c:	8de1      	ldrh	r1, [r4, #46]	@ 0x2e
 800477e:	1a40      	subs	r0, r0, r1
 8004780:	8028      	strh	r0, [r5, #0]
 8004782:	2020      	movs	r0, #32
 8004784:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8004788:	2000      	movs	r0, #0
 800478a:	e77e      	b.n	800468a <HAL_UARTEx_ReceiveToIdle+0x22>
 800478c:	2002      	movs	r0, #2
 800478e:	e77c      	b.n	800468a <HAL_UARTEx_ReceiveToIdle+0x22>

08004790 <HAL_UARTEx_ReceiveToIdle_DMA>:
 8004790:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8004792:	4604      	mov	r4, r0
 8004794:	460d      	mov	r5, r1
 8004796:	4616      	mov	r6, r2
 8004798:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 800479c:	2820      	cmp	r0, #32
 800479e:	d12d      	bne.n	80047fc <HAL_UARTEx_ReceiveToIdle_DMA+0x6c>
 80047a0:	b105      	cbz	r5, 80047a4 <HAL_UARTEx_ReceiveToIdle_DMA+0x14>
 80047a2:	b90e      	cbnz	r6, 80047a8 <HAL_UARTEx_ReceiveToIdle_DMA+0x18>
 80047a4:	2001      	movs	r0, #1
 80047a6:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 80047a8:	2001      	movs	r0, #1
 80047aa:	6320      	str	r0, [r4, #48]	@ 0x30
 80047ac:	2000      	movs	r0, #0
 80047ae:	6360      	str	r0, [r4, #52]	@ 0x34
 80047b0:	4632      	mov	r2, r6
 80047b2:	4629      	mov	r1, r5
 80047b4:	4620      	mov	r0, r4
 80047b6:	f001 fac7 	bl	8005d48 <UART_Start_Receive_DMA>
 80047ba:	4607      	mov	r7, r0
 80047bc:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 80047be:	2801      	cmp	r0, #1
 80047c0:	d119      	bne.n	80047f6 <HAL_UARTEx_ReceiveToIdle_DMA+0x66>
 80047c2:	bf00      	nop
 80047c4:	2000      	movs	r0, #0
 80047c6:	9000      	str	r0, [sp, #0]
 80047c8:	6820      	ldr	r0, [r4, #0]
 80047ca:	6800      	ldr	r0, [r0, #0]
 80047cc:	9000      	str	r0, [sp, #0]
 80047ce:	6820      	ldr	r0, [r4, #0]
 80047d0:	6840      	ldr	r0, [r0, #4]
 80047d2:	9000      	str	r0, [sp, #0]
 80047d4:	bf00      	nop
 80047d6:	bf00      	nop
 80047d8:	bf00      	nop
 80047da:	bf00      	nop
 80047dc:	6821      	ldr	r1, [r4, #0]
 80047de:	310c      	adds	r1, #12
 80047e0:	e851 1f00 	ldrex	r1, [r1]
 80047e4:	f041 0010 	orr.w	r0, r1, #16
 80047e8:	6821      	ldr	r1, [r4, #0]
 80047ea:	310c      	adds	r1, #12
 80047ec:	e841 0200 	strex	r2, r0, [r1]
 80047f0:	2a00      	cmp	r2, #0
 80047f2:	d1f3      	bne.n	80047dc <HAL_UARTEx_ReceiveToIdle_DMA+0x4c>
 80047f4:	e000      	b.n	80047f8 <HAL_UARTEx_ReceiveToIdle_DMA+0x68>
 80047f6:	2701      	movs	r7, #1
 80047f8:	4638      	mov	r0, r7
 80047fa:	e7d4      	b.n	80047a6 <HAL_UARTEx_ReceiveToIdle_DMA+0x16>
 80047fc:	2002      	movs	r0, #2
 80047fe:	e7d2      	b.n	80047a6 <HAL_UARTEx_ReceiveToIdle_DMA+0x16>

08004800 <HAL_UARTEx_ReceiveToIdle_IT>:
 8004800:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8004802:	4604      	mov	r4, r0
 8004804:	460e      	mov	r6, r1
 8004806:	4617      	mov	r7, r2
 8004808:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 800480c:	2820      	cmp	r0, #32
 800480e:	d12e      	bne.n	800486e <HAL_UARTEx_ReceiveToIdle_IT+0x6e>
 8004810:	b106      	cbz	r6, 8004814 <HAL_UARTEx_ReceiveToIdle_IT+0x14>
 8004812:	b90f      	cbnz	r7, 8004818 <HAL_UARTEx_ReceiveToIdle_IT+0x18>
 8004814:	2001      	movs	r0, #1
 8004816:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 8004818:	2001      	movs	r0, #1
 800481a:	6320      	str	r0, [r4, #48]	@ 0x30
 800481c:	2000      	movs	r0, #0
 800481e:	6360      	str	r0, [r4, #52]	@ 0x34
 8004820:	463a      	mov	r2, r7
 8004822:	4631      	mov	r1, r6
 8004824:	4620      	mov	r0, r4
 8004826:	f001 faf3 	bl	8005e10 <UART_Start_Receive_IT>
 800482a:	4605      	mov	r5, r0
 800482c:	b9ed      	cbnz	r5, 800486a <HAL_UARTEx_ReceiveToIdle_IT+0x6a>
 800482e:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 8004830:	2801      	cmp	r0, #1
 8004832:	d119      	bne.n	8004868 <HAL_UARTEx_ReceiveToIdle_IT+0x68>
 8004834:	bf00      	nop
 8004836:	2000      	movs	r0, #0
 8004838:	9000      	str	r0, [sp, #0]
 800483a:	6820      	ldr	r0, [r4, #0]
 800483c:	6800      	ldr	r0, [r0, #0]
 800483e:	9000      	str	r0, [sp, #0]
 8004840:	6820      	ldr	r0, [r4, #0]
 8004842:	6840      	ldr	r0, [r0, #4]
 8004844:	9000      	str	r0, [sp, #0]
 8004846:	bf00      	nop
 8004848:	bf00      	nop
 800484a:	bf00      	nop
 800484c:	bf00      	nop
 800484e:	6821      	ldr	r1, [r4, #0]
 8004850:	310c      	adds	r1, #12
 8004852:	e851 1f00 	ldrex	r1, [r1]
 8004856:	f041 0010 	orr.w	r0, r1, #16
 800485a:	6821      	ldr	r1, [r4, #0]
 800485c:	310c      	adds	r1, #12
 800485e:	e841 0200 	strex	r2, r0, [r1]
 8004862:	2a00      	cmp	r2, #0
 8004864:	d1f3      	bne.n	800484e <HAL_UARTEx_ReceiveToIdle_IT+0x4e>
 8004866:	e000      	b.n	800486a <HAL_UARTEx_ReceiveToIdle_IT+0x6a>
 8004868:	2501      	movs	r5, #1
 800486a:	4628      	mov	r0, r5
 800486c:	e7d3      	b.n	8004816 <HAL_UARTEx_ReceiveToIdle_IT+0x16>
 800486e:	2002      	movs	r0, #2
 8004870:	e7d1      	b.n	8004816 <HAL_UARTEx_ReceiveToIdle_IT+0x16>

08004872 <HAL_UARTEx_RxEventCallback>:
 8004872:	4770      	bx	lr

08004874 <HAL_UART_Abort>:
 8004874:	b510      	push	{r4, lr}
 8004876:	4604      	mov	r4, r0
 8004878:	bf00      	nop
 800487a:	bf00      	nop
 800487c:	6821      	ldr	r1, [r4, #0]
 800487e:	310c      	adds	r1, #12
 8004880:	e851 1f00 	ldrex	r1, [r1]
 8004884:	f421 70f0 	bic.w	r0, r1, #480	@ 0x1e0
 8004888:	6821      	ldr	r1, [r4, #0]
 800488a:	310c      	adds	r1, #12
 800488c:	e841 0200 	strex	r2, r0, [r1]
 8004890:	2a00      	cmp	r2, #0
 8004892:	d1f3      	bne.n	800487c <HAL_UART_Abort+0x8>
 8004894:	bf00      	nop
 8004896:	bf00      	nop
 8004898:	bf00      	nop
 800489a:	6821      	ldr	r1, [r4, #0]
 800489c:	3114      	adds	r1, #20
 800489e:	e851 1f00 	ldrex	r1, [r1]
 80048a2:	f021 0001 	bic.w	r0, r1, #1
 80048a6:	6821      	ldr	r1, [r4, #0]
 80048a8:	3114      	adds	r1, #20
 80048aa:	e841 0200 	strex	r2, r0, [r1]
 80048ae:	2a00      	cmp	r2, #0
 80048b0:	d1f3      	bne.n	800489a <HAL_UART_Abort+0x26>
 80048b2:	bf00      	nop
 80048b4:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 80048b6:	2801      	cmp	r0, #1
 80048b8:	d10e      	bne.n	80048d8 <HAL_UART_Abort+0x64>
 80048ba:	bf00      	nop
 80048bc:	bf00      	nop
 80048be:	6821      	ldr	r1, [r4, #0]
 80048c0:	310c      	adds	r1, #12
 80048c2:	e851 1f00 	ldrex	r1, [r1]
 80048c6:	f021 0010 	bic.w	r0, r1, #16
 80048ca:	6821      	ldr	r1, [r4, #0]
 80048cc:	310c      	adds	r1, #12
 80048ce:	e841 0200 	strex	r2, r0, [r1]
 80048d2:	2a00      	cmp	r2, #0
 80048d4:	d1f3      	bne.n	80048be <HAL_UART_Abort+0x4a>
 80048d6:	bf00      	nop
 80048d8:	6820      	ldr	r0, [r4, #0]
 80048da:	6940      	ldr	r0, [r0, #20]
 80048dc:	f000 0080 	and.w	r0, r0, #128	@ 0x80
 80048e0:	b300      	cbz	r0, 8004924 <HAL_UART_Abort+0xb0>
 80048e2:	bf00      	nop
 80048e4:	bf00      	nop
 80048e6:	6821      	ldr	r1, [r4, #0]
 80048e8:	3114      	adds	r1, #20
 80048ea:	e851 1f00 	ldrex	r1, [r1]
 80048ee:	f021 0080 	bic.w	r0, r1, #128	@ 0x80
 80048f2:	6821      	ldr	r1, [r4, #0]
 80048f4:	3114      	adds	r1, #20
 80048f6:	e841 0200 	strex	r2, r0, [r1]
 80048fa:	2a00      	cmp	r2, #0
 80048fc:	d1f3      	bne.n	80048e6 <HAL_UART_Abort+0x72>
 80048fe:	bf00      	nop
 8004900:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004902:	b178      	cbz	r0, 8004924 <HAL_UART_Abort+0xb0>
 8004904:	2000      	movs	r0, #0
 8004906:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8004908:	6348      	str	r0, [r1, #52]	@ 0x34
 800490a:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 800490c:	f7fc fd3c 	bl	8001388 <HAL_DMA_Abort>
 8004910:	b140      	cbz	r0, 8004924 <HAL_UART_Abort+0xb0>
 8004912:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004914:	f7fc fe7e 	bl	8001614 <HAL_DMA_GetError>
 8004918:	2820      	cmp	r0, #32
 800491a:	d103      	bne.n	8004924 <HAL_UART_Abort+0xb0>
 800491c:	2010      	movs	r0, #16
 800491e:	6460      	str	r0, [r4, #68]	@ 0x44
 8004920:	2003      	movs	r0, #3
 8004922:	bd10      	pop	{r4, pc}
 8004924:	6820      	ldr	r0, [r4, #0]
 8004926:	6940      	ldr	r0, [r0, #20]
 8004928:	f000 0040 	and.w	r0, r0, #64	@ 0x40
 800492c:	b300      	cbz	r0, 8004970 <HAL_UART_Abort+0xfc>
 800492e:	bf00      	nop
 8004930:	bf00      	nop
 8004932:	6821      	ldr	r1, [r4, #0]
 8004934:	3114      	adds	r1, #20
 8004936:	e851 1f00 	ldrex	r1, [r1]
 800493a:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 800493e:	6821      	ldr	r1, [r4, #0]
 8004940:	3114      	adds	r1, #20
 8004942:	e841 0200 	strex	r2, r0, [r1]
 8004946:	2a00      	cmp	r2, #0
 8004948:	d1f3      	bne.n	8004932 <HAL_UART_Abort+0xbe>
 800494a:	bf00      	nop
 800494c:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 800494e:	b178      	cbz	r0, 8004970 <HAL_UART_Abort+0xfc>
 8004950:	2000      	movs	r0, #0
 8004952:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8004954:	6348      	str	r0, [r1, #52]	@ 0x34
 8004956:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004958:	f7fc fd16 	bl	8001388 <HAL_DMA_Abort>
 800495c:	b140      	cbz	r0, 8004970 <HAL_UART_Abort+0xfc>
 800495e:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004960:	f7fc fe58 	bl	8001614 <HAL_DMA_GetError>
 8004964:	2820      	cmp	r0, #32
 8004966:	d103      	bne.n	8004970 <HAL_UART_Abort+0xfc>
 8004968:	2010      	movs	r0, #16
 800496a:	6460      	str	r0, [r4, #68]	@ 0x44
 800496c:	2003      	movs	r0, #3
 800496e:	e7d8      	b.n	8004922 <HAL_UART_Abort+0xae>
 8004970:	2000      	movs	r0, #0
 8004972:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8004974:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8004976:	6460      	str	r0, [r4, #68]	@ 0x44
 8004978:	2020      	movs	r0, #32
 800497a:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 800497e:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8004982:	2000      	movs	r0, #0
 8004984:	6320      	str	r0, [r4, #48]	@ 0x30
 8004986:	bf00      	nop
 8004988:	e7cb      	b.n	8004922 <HAL_UART_Abort+0xae>

0800498a <HAL_UART_AbortCpltCallback>:
 800498a:	4770      	bx	lr

0800498c <HAL_UART_AbortReceive>:
 800498c:	b510      	push	{r4, lr}
 800498e:	4604      	mov	r4, r0
 8004990:	bf00      	nop
 8004992:	bf00      	nop
 8004994:	6821      	ldr	r1, [r4, #0]
 8004996:	310c      	adds	r1, #12
 8004998:	e851 1f00 	ldrex	r1, [r1]
 800499c:	f421 7090 	bic.w	r0, r1, #288	@ 0x120
 80049a0:	6821      	ldr	r1, [r4, #0]
 80049a2:	310c      	adds	r1, #12
 80049a4:	e841 0200 	strex	r2, r0, [r1]
 80049a8:	2a00      	cmp	r2, #0
 80049aa:	d1f3      	bne.n	8004994 <HAL_UART_AbortReceive+0x8>
 80049ac:	bf00      	nop
 80049ae:	bf00      	nop
 80049b0:	bf00      	nop
 80049b2:	6821      	ldr	r1, [r4, #0]
 80049b4:	3114      	adds	r1, #20
 80049b6:	e851 1f00 	ldrex	r1, [r1]
 80049ba:	f021 0001 	bic.w	r0, r1, #1
 80049be:	6821      	ldr	r1, [r4, #0]
 80049c0:	3114      	adds	r1, #20
 80049c2:	e841 0200 	strex	r2, r0, [r1]
 80049c6:	2a00      	cmp	r2, #0
 80049c8:	d1f3      	bne.n	80049b2 <HAL_UART_AbortReceive+0x26>
 80049ca:	bf00      	nop
 80049cc:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 80049ce:	2801      	cmp	r0, #1
 80049d0:	d10e      	bne.n	80049f0 <HAL_UART_AbortReceive+0x64>
 80049d2:	bf00      	nop
 80049d4:	bf00      	nop
 80049d6:	6821      	ldr	r1, [r4, #0]
 80049d8:	310c      	adds	r1, #12
 80049da:	e851 1f00 	ldrex	r1, [r1]
 80049de:	f021 0010 	bic.w	r0, r1, #16
 80049e2:	6821      	ldr	r1, [r4, #0]
 80049e4:	310c      	adds	r1, #12
 80049e6:	e841 0200 	strex	r2, r0, [r1]
 80049ea:	2a00      	cmp	r2, #0
 80049ec:	d1f3      	bne.n	80049d6 <HAL_UART_AbortReceive+0x4a>
 80049ee:	bf00      	nop
 80049f0:	6820      	ldr	r0, [r4, #0]
 80049f2:	6940      	ldr	r0, [r0, #20]
 80049f4:	f000 0040 	and.w	r0, r0, #64	@ 0x40
 80049f8:	b300      	cbz	r0, 8004a3c <HAL_UART_AbortReceive+0xb0>
 80049fa:	bf00      	nop
 80049fc:	bf00      	nop
 80049fe:	6821      	ldr	r1, [r4, #0]
 8004a00:	3114      	adds	r1, #20
 8004a02:	e851 1f00 	ldrex	r1, [r1]
 8004a06:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 8004a0a:	6821      	ldr	r1, [r4, #0]
 8004a0c:	3114      	adds	r1, #20
 8004a0e:	e841 0200 	strex	r2, r0, [r1]
 8004a12:	2a00      	cmp	r2, #0
 8004a14:	d1f3      	bne.n	80049fe <HAL_UART_AbortReceive+0x72>
 8004a16:	bf00      	nop
 8004a18:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004a1a:	b178      	cbz	r0, 8004a3c <HAL_UART_AbortReceive+0xb0>
 8004a1c:	2000      	movs	r0, #0
 8004a1e:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8004a20:	6348      	str	r0, [r1, #52]	@ 0x34
 8004a22:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004a24:	f7fc fcb0 	bl	8001388 <HAL_DMA_Abort>
 8004a28:	b140      	cbz	r0, 8004a3c <HAL_UART_AbortReceive+0xb0>
 8004a2a:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004a2c:	f7fc fdf2 	bl	8001614 <HAL_DMA_GetError>
 8004a30:	2820      	cmp	r0, #32
 8004a32:	d103      	bne.n	8004a3c <HAL_UART_AbortReceive+0xb0>
 8004a34:	2010      	movs	r0, #16
 8004a36:	6460      	str	r0, [r4, #68]	@ 0x44
 8004a38:	2003      	movs	r0, #3
 8004a3a:	bd10      	pop	{r4, pc}
 8004a3c:	2000      	movs	r0, #0
 8004a3e:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8004a40:	2020      	movs	r0, #32
 8004a42:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8004a46:	2000      	movs	r0, #0
 8004a48:	6320      	str	r0, [r4, #48]	@ 0x30
 8004a4a:	bf00      	nop
 8004a4c:	e7f5      	b.n	8004a3a <HAL_UART_AbortReceive+0xae>

08004a4e <HAL_UART_AbortReceiveCpltCallback>:
 8004a4e:	4770      	bx	lr

08004a50 <HAL_UART_AbortReceive_IT>:
 8004a50:	b510      	push	{r4, lr}
 8004a52:	4604      	mov	r4, r0
 8004a54:	bf00      	nop
 8004a56:	bf00      	nop
 8004a58:	6821      	ldr	r1, [r4, #0]
 8004a5a:	310c      	adds	r1, #12
 8004a5c:	e851 1f00 	ldrex	r1, [r1]
 8004a60:	f421 7090 	bic.w	r0, r1, #288	@ 0x120
 8004a64:	6821      	ldr	r1, [r4, #0]
 8004a66:	310c      	adds	r1, #12
 8004a68:	e841 0200 	strex	r2, r0, [r1]
 8004a6c:	2a00      	cmp	r2, #0
 8004a6e:	d1f3      	bne.n	8004a58 <HAL_UART_AbortReceive_IT+0x8>
 8004a70:	bf00      	nop
 8004a72:	bf00      	nop
 8004a74:	bf00      	nop
 8004a76:	6821      	ldr	r1, [r4, #0]
 8004a78:	3114      	adds	r1, #20
 8004a7a:	e851 1f00 	ldrex	r1, [r1]
 8004a7e:	f021 0001 	bic.w	r0, r1, #1
 8004a82:	6821      	ldr	r1, [r4, #0]
 8004a84:	3114      	adds	r1, #20
 8004a86:	e841 0200 	strex	r2, r0, [r1]
 8004a8a:	2a00      	cmp	r2, #0
 8004a8c:	d1f3      	bne.n	8004a76 <HAL_UART_AbortReceive_IT+0x26>
 8004a8e:	bf00      	nop
 8004a90:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 8004a92:	2801      	cmp	r0, #1
 8004a94:	d10e      	bne.n	8004ab4 <HAL_UART_AbortReceive_IT+0x64>
 8004a96:	bf00      	nop
 8004a98:	bf00      	nop
 8004a9a:	6821      	ldr	r1, [r4, #0]
 8004a9c:	310c      	adds	r1, #12
 8004a9e:	e851 1f00 	ldrex	r1, [r1]
 8004aa2:	f021 0010 	bic.w	r0, r1, #16
 8004aa6:	6821      	ldr	r1, [r4, #0]
 8004aa8:	310c      	adds	r1, #12
 8004aaa:	e841 0200 	strex	r2, r0, [r1]
 8004aae:	2a00      	cmp	r2, #0
 8004ab0:	d1f3      	bne.n	8004a9a <HAL_UART_AbortReceive_IT+0x4a>
 8004ab2:	bf00      	nop
 8004ab4:	6820      	ldr	r0, [r4, #0]
 8004ab6:	6940      	ldr	r0, [r0, #20]
 8004ab8:	f000 0040 	and.w	r0, r0, #64	@ 0x40
 8004abc:	b330      	cbz	r0, 8004b0c <HAL_UART_AbortReceive_IT+0xbc>
 8004abe:	bf00      	nop
 8004ac0:	bf00      	nop
 8004ac2:	6821      	ldr	r1, [r4, #0]
 8004ac4:	3114      	adds	r1, #20
 8004ac6:	e851 1f00 	ldrex	r1, [r1]
 8004aca:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 8004ace:	6821      	ldr	r1, [r4, #0]
 8004ad0:	3114      	adds	r1, #20
 8004ad2:	e841 0200 	strex	r2, r0, [r1]
 8004ad6:	2a00      	cmp	r2, #0
 8004ad8:	d1f3      	bne.n	8004ac2 <HAL_UART_AbortReceive_IT+0x72>
 8004ada:	bf00      	nop
 8004adc:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004ade:	b150      	cbz	r0, 8004af6 <HAL_UART_AbortReceive_IT+0xa6>
 8004ae0:	4810      	ldr	r0, [pc, #64]	@ (8004b24 <HAL_UART_AbortReceive_IT+0xd4>)
 8004ae2:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8004ae4:	6348      	str	r0, [r1, #52]	@ 0x34
 8004ae6:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004ae8:	f7fc fc7a 	bl	80013e0 <HAL_DMA_Abort_IT>
 8004aec:	b1c0      	cbz	r0, 8004b20 <HAL_UART_AbortReceive_IT+0xd0>
 8004aee:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004af0:	6b41      	ldr	r1, [r0, #52]	@ 0x34
 8004af2:	4788      	blx	r1
 8004af4:	e014      	b.n	8004b20 <HAL_UART_AbortReceive_IT+0xd0>
 8004af6:	2000      	movs	r0, #0
 8004af8:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8004afa:	2020      	movs	r0, #32
 8004afc:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8004b00:	2000      	movs	r0, #0
 8004b02:	6320      	str	r0, [r4, #48]	@ 0x30
 8004b04:	4620      	mov	r0, r4
 8004b06:	f7ff ffa2 	bl	8004a4e <HAL_UART_AbortReceiveCpltCallback>
 8004b0a:	e009      	b.n	8004b20 <HAL_UART_AbortReceive_IT+0xd0>
 8004b0c:	2000      	movs	r0, #0
 8004b0e:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8004b10:	2020      	movs	r0, #32
 8004b12:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8004b16:	2000      	movs	r0, #0
 8004b18:	6320      	str	r0, [r4, #48]	@ 0x30
 8004b1a:	4620      	mov	r0, r4
 8004b1c:	f7ff ff97 	bl	8004a4e <HAL_UART_AbortReceiveCpltCallback>
 8004b20:	2000      	movs	r0, #0
 8004b22:	bd10      	pop	{r4, pc}
 8004b24:	080059cb 	.word	0x080059cb

08004b28 <HAL_UART_AbortTransmit>:
 8004b28:	b510      	push	{r4, lr}
 8004b2a:	4604      	mov	r4, r0
 8004b2c:	bf00      	nop
 8004b2e:	bf00      	nop
 8004b30:	6821      	ldr	r1, [r4, #0]
 8004b32:	310c      	adds	r1, #12
 8004b34:	e851 1f00 	ldrex	r1, [r1]
 8004b38:	f021 00c0 	bic.w	r0, r1, #192	@ 0xc0
 8004b3c:	6821      	ldr	r1, [r4, #0]
 8004b3e:	310c      	adds	r1, #12
 8004b40:	e841 0200 	strex	r2, r0, [r1]
 8004b44:	2a00      	cmp	r2, #0
 8004b46:	d1f3      	bne.n	8004b30 <HAL_UART_AbortTransmit+0x8>
 8004b48:	bf00      	nop
 8004b4a:	6820      	ldr	r0, [r4, #0]
 8004b4c:	6940      	ldr	r0, [r0, #20]
 8004b4e:	f000 0080 	and.w	r0, r0, #128	@ 0x80
 8004b52:	b300      	cbz	r0, 8004b96 <HAL_UART_AbortTransmit+0x6e>
 8004b54:	bf00      	nop
 8004b56:	bf00      	nop
 8004b58:	6821      	ldr	r1, [r4, #0]
 8004b5a:	3114      	adds	r1, #20
 8004b5c:	e851 1f00 	ldrex	r1, [r1]
 8004b60:	f021 0080 	bic.w	r0, r1, #128	@ 0x80
 8004b64:	6821      	ldr	r1, [r4, #0]
 8004b66:	3114      	adds	r1, #20
 8004b68:	e841 0200 	strex	r2, r0, [r1]
 8004b6c:	2a00      	cmp	r2, #0
 8004b6e:	d1f3      	bne.n	8004b58 <HAL_UART_AbortTransmit+0x30>
 8004b70:	bf00      	nop
 8004b72:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004b74:	b178      	cbz	r0, 8004b96 <HAL_UART_AbortTransmit+0x6e>
 8004b76:	2000      	movs	r0, #0
 8004b78:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8004b7a:	6348      	str	r0, [r1, #52]	@ 0x34
 8004b7c:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004b7e:	f7fc fc03 	bl	8001388 <HAL_DMA_Abort>
 8004b82:	b140      	cbz	r0, 8004b96 <HAL_UART_AbortTransmit+0x6e>
 8004b84:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004b86:	f7fc fd45 	bl	8001614 <HAL_DMA_GetError>
 8004b8a:	2820      	cmp	r0, #32
 8004b8c:	d103      	bne.n	8004b96 <HAL_UART_AbortTransmit+0x6e>
 8004b8e:	2010      	movs	r0, #16
 8004b90:	6460      	str	r0, [r4, #68]	@ 0x44
 8004b92:	2003      	movs	r0, #3
 8004b94:	bd10      	pop	{r4, pc}
 8004b96:	2000      	movs	r0, #0
 8004b98:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8004b9a:	2020      	movs	r0, #32
 8004b9c:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8004ba0:	2000      	movs	r0, #0
 8004ba2:	e7f7      	b.n	8004b94 <HAL_UART_AbortTransmit+0x6c>

08004ba4 <HAL_UART_AbortTransmitCpltCallback>:
 8004ba4:	4770      	bx	lr
	...

08004ba8 <HAL_UART_AbortTransmit_IT>:
 8004ba8:	b510      	push	{r4, lr}
 8004baa:	4604      	mov	r4, r0
 8004bac:	bf00      	nop
 8004bae:	bf00      	nop
 8004bb0:	6821      	ldr	r1, [r4, #0]
 8004bb2:	310c      	adds	r1, #12
 8004bb4:	e851 1f00 	ldrex	r1, [r1]
 8004bb8:	f021 00c0 	bic.w	r0, r1, #192	@ 0xc0
 8004bbc:	6821      	ldr	r1, [r4, #0]
 8004bbe:	310c      	adds	r1, #12
 8004bc0:	e841 0200 	strex	r2, r0, [r1]
 8004bc4:	2a00      	cmp	r2, #0
 8004bc6:	d1f3      	bne.n	8004bb0 <HAL_UART_AbortTransmit_IT+0x8>
 8004bc8:	bf00      	nop
 8004bca:	6820      	ldr	r0, [r4, #0]
 8004bcc:	6940      	ldr	r0, [r0, #20]
 8004bce:	f000 0080 	and.w	r0, r0, #128	@ 0x80
 8004bd2:	b320      	cbz	r0, 8004c1e <HAL_UART_AbortTransmit_IT+0x76>
 8004bd4:	bf00      	nop
 8004bd6:	bf00      	nop
 8004bd8:	6821      	ldr	r1, [r4, #0]
 8004bda:	3114      	adds	r1, #20
 8004bdc:	e851 1f00 	ldrex	r1, [r1]
 8004be0:	f021 0080 	bic.w	r0, r1, #128	@ 0x80
 8004be4:	6821      	ldr	r1, [r4, #0]
 8004be6:	3114      	adds	r1, #20
 8004be8:	e841 0200 	strex	r2, r0, [r1]
 8004bec:	2a00      	cmp	r2, #0
 8004bee:	d1f3      	bne.n	8004bd8 <HAL_UART_AbortTransmit_IT+0x30>
 8004bf0:	bf00      	nop
 8004bf2:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004bf4:	b150      	cbz	r0, 8004c0c <HAL_UART_AbortTransmit_IT+0x64>
 8004bf6:	480f      	ldr	r0, [pc, #60]	@ (8004c34 <HAL_UART_AbortTransmit_IT+0x8c>)
 8004bf8:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8004bfa:	6348      	str	r0, [r1, #52]	@ 0x34
 8004bfc:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004bfe:	f7fc fbef 	bl	80013e0 <HAL_DMA_Abort_IT>
 8004c02:	b1a0      	cbz	r0, 8004c2e <HAL_UART_AbortTransmit_IT+0x86>
 8004c04:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004c06:	6b41      	ldr	r1, [r0, #52]	@ 0x34
 8004c08:	4788      	blx	r1
 8004c0a:	e010      	b.n	8004c2e <HAL_UART_AbortTransmit_IT+0x86>
 8004c0c:	2000      	movs	r0, #0
 8004c0e:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8004c10:	2020      	movs	r0, #32
 8004c12:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8004c16:	4620      	mov	r0, r4
 8004c18:	f7ff ffc4 	bl	8004ba4 <HAL_UART_AbortTransmitCpltCallback>
 8004c1c:	e007      	b.n	8004c2e <HAL_UART_AbortTransmit_IT+0x86>
 8004c1e:	2000      	movs	r0, #0
 8004c20:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8004c22:	2020      	movs	r0, #32
 8004c24:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8004c28:	4620      	mov	r0, r4
 8004c2a:	f7ff ffbb 	bl	8004ba4 <HAL_UART_AbortTransmitCpltCallback>
 8004c2e:	2000      	movs	r0, #0
 8004c30:	bd10      	pop	{r4, pc}
 8004c32:	0000      	.short	0x0000
 8004c34:	08005a85 	.word	0x08005a85

08004c38 <HAL_UART_Abort_IT>:
 8004c38:	b570      	push	{r4, r5, r6, lr}
 8004c3a:	4604      	mov	r4, r0
 8004c3c:	2501      	movs	r5, #1
 8004c3e:	bf00      	nop
 8004c40:	bf00      	nop
 8004c42:	6821      	ldr	r1, [r4, #0]
 8004c44:	310c      	adds	r1, #12
 8004c46:	e851 1f00 	ldrex	r1, [r1]
 8004c4a:	f421 70f0 	bic.w	r0, r1, #480	@ 0x1e0
 8004c4e:	6821      	ldr	r1, [r4, #0]
 8004c50:	310c      	adds	r1, #12
 8004c52:	e841 0200 	strex	r2, r0, [r1]
 8004c56:	2a00      	cmp	r2, #0
 8004c58:	d1f3      	bne.n	8004c42 <HAL_UART_Abort_IT+0xa>
 8004c5a:	bf00      	nop
 8004c5c:	bf00      	nop
 8004c5e:	bf00      	nop
 8004c60:	6821      	ldr	r1, [r4, #0]
 8004c62:	3114      	adds	r1, #20
 8004c64:	e851 1f00 	ldrex	r1, [r1]
 8004c68:	f021 0001 	bic.w	r0, r1, #1
 8004c6c:	6821      	ldr	r1, [r4, #0]
 8004c6e:	3114      	adds	r1, #20
 8004c70:	e841 0200 	strex	r2, r0, [r1]
 8004c74:	2a00      	cmp	r2, #0
 8004c76:	d1f3      	bne.n	8004c60 <HAL_UART_Abort_IT+0x28>
 8004c78:	bf00      	nop
 8004c7a:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 8004c7c:	2801      	cmp	r0, #1
 8004c7e:	d10e      	bne.n	8004c9e <HAL_UART_Abort_IT+0x66>
 8004c80:	bf00      	nop
 8004c82:	bf00      	nop
 8004c84:	6821      	ldr	r1, [r4, #0]
 8004c86:	310c      	adds	r1, #12
 8004c88:	e851 1f00 	ldrex	r1, [r1]
 8004c8c:	f021 0010 	bic.w	r0, r1, #16
 8004c90:	6821      	ldr	r1, [r4, #0]
 8004c92:	310c      	adds	r1, #12
 8004c94:	e841 0200 	strex	r2, r0, [r1]
 8004c98:	2a00      	cmp	r2, #0
 8004c9a:	d1f3      	bne.n	8004c84 <HAL_UART_Abort_IT+0x4c>
 8004c9c:	bf00      	nop
 8004c9e:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004ca0:	b158      	cbz	r0, 8004cba <HAL_UART_Abort_IT+0x82>
 8004ca2:	6820      	ldr	r0, [r4, #0]
 8004ca4:	6940      	ldr	r0, [r0, #20]
 8004ca6:	f000 0080 	and.w	r0, r0, #128	@ 0x80
 8004caa:	b118      	cbz	r0, 8004cb4 <HAL_UART_Abort_IT+0x7c>
 8004cac:	4832      	ldr	r0, [pc, #200]	@ (8004d78 <HAL_UART_Abort_IT+0x140>)
 8004cae:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8004cb0:	6348      	str	r0, [r1, #52]	@ 0x34
 8004cb2:	e002      	b.n	8004cba <HAL_UART_Abort_IT+0x82>
 8004cb4:	2000      	movs	r0, #0
 8004cb6:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8004cb8:	6348      	str	r0, [r1, #52]	@ 0x34
 8004cba:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004cbc:	b158      	cbz	r0, 8004cd6 <HAL_UART_Abort_IT+0x9e>
 8004cbe:	6820      	ldr	r0, [r4, #0]
 8004cc0:	6940      	ldr	r0, [r0, #20]
 8004cc2:	f000 0040 	and.w	r0, r0, #64	@ 0x40
 8004cc6:	b118      	cbz	r0, 8004cd0 <HAL_UART_Abort_IT+0x98>
 8004cc8:	482c      	ldr	r0, [pc, #176]	@ (8004d7c <HAL_UART_Abort_IT+0x144>)
 8004cca:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8004ccc:	6348      	str	r0, [r1, #52]	@ 0x34
 8004cce:	e002      	b.n	8004cd6 <HAL_UART_Abort_IT+0x9e>
 8004cd0:	2000      	movs	r0, #0
 8004cd2:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8004cd4:	6348      	str	r0, [r1, #52]	@ 0x34
 8004cd6:	6820      	ldr	r0, [r4, #0]
 8004cd8:	6940      	ldr	r0, [r0, #20]
 8004cda:	f000 0080 	and.w	r0, r0, #128	@ 0x80
 8004cde:	b1c8      	cbz	r0, 8004d14 <HAL_UART_Abort_IT+0xdc>
 8004ce0:	bf00      	nop
 8004ce2:	bf00      	nop
 8004ce4:	6821      	ldr	r1, [r4, #0]
 8004ce6:	3114      	adds	r1, #20
 8004ce8:	e851 1f00 	ldrex	r1, [r1]
 8004cec:	f021 0080 	bic.w	r0, r1, #128	@ 0x80
 8004cf0:	6821      	ldr	r1, [r4, #0]
 8004cf2:	3114      	adds	r1, #20
 8004cf4:	e841 0200 	strex	r2, r0, [r1]
 8004cf8:	2a00      	cmp	r2, #0
 8004cfa:	d1f3      	bne.n	8004ce4 <HAL_UART_Abort_IT+0xac>
 8004cfc:	bf00      	nop
 8004cfe:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004d00:	b140      	cbz	r0, 8004d14 <HAL_UART_Abort_IT+0xdc>
 8004d02:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004d04:	f7fc fb6c 	bl	80013e0 <HAL_DMA_Abort_IT>
 8004d08:	b118      	cbz	r0, 8004d12 <HAL_UART_Abort_IT+0xda>
 8004d0a:	2000      	movs	r0, #0
 8004d0c:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8004d0e:	6348      	str	r0, [r1, #52]	@ 0x34
 8004d10:	e000      	b.n	8004d14 <HAL_UART_Abort_IT+0xdc>
 8004d12:	2500      	movs	r5, #0
 8004d14:	6820      	ldr	r0, [r4, #0]
 8004d16:	6940      	ldr	r0, [r0, #20]
 8004d18:	f000 0040 	and.w	r0, r0, #64	@ 0x40
 8004d1c:	b1d0      	cbz	r0, 8004d54 <HAL_UART_Abort_IT+0x11c>
 8004d1e:	bf00      	nop
 8004d20:	bf00      	nop
 8004d22:	6821      	ldr	r1, [r4, #0]
 8004d24:	3114      	adds	r1, #20
 8004d26:	e851 1f00 	ldrex	r1, [r1]
 8004d2a:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 8004d2e:	6821      	ldr	r1, [r4, #0]
 8004d30:	3114      	adds	r1, #20
 8004d32:	e841 0200 	strex	r2, r0, [r1]
 8004d36:	2a00      	cmp	r2, #0
 8004d38:	d1f3      	bne.n	8004d22 <HAL_UART_Abort_IT+0xea>
 8004d3a:	bf00      	nop
 8004d3c:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004d3e:	b148      	cbz	r0, 8004d54 <HAL_UART_Abort_IT+0x11c>
 8004d40:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004d42:	f7fc fb4d 	bl	80013e0 <HAL_DMA_Abort_IT>
 8004d46:	b120      	cbz	r0, 8004d52 <HAL_UART_Abort_IT+0x11a>
 8004d48:	2000      	movs	r0, #0
 8004d4a:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8004d4c:	6348      	str	r0, [r1, #52]	@ 0x34
 8004d4e:	2501      	movs	r5, #1
 8004d50:	e000      	b.n	8004d54 <HAL_UART_Abort_IT+0x11c>
 8004d52:	2500      	movs	r5, #0
 8004d54:	2d01      	cmp	r5, #1
 8004d56:	d10d      	bne.n	8004d74 <HAL_UART_Abort_IT+0x13c>
 8004d58:	2000      	movs	r0, #0
 8004d5a:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8004d5c:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8004d5e:	6460      	str	r0, [r4, #68]	@ 0x44
 8004d60:	2020      	movs	r0, #32
 8004d62:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8004d66:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8004d6a:	2000      	movs	r0, #0
 8004d6c:	6320      	str	r0, [r4, #48]	@ 0x30
 8004d6e:	4620      	mov	r0, r4
 8004d70:	f7ff fe0b 	bl	800498a <HAL_UART_AbortCpltCallback>
 8004d74:	2000      	movs	r0, #0
 8004d76:	bd70      	pop	{r4, r5, r6, pc}
 8004d78:	08005a3f 	.word	0x08005a3f
 8004d7c:	0800596f 	.word	0x0800596f

08004d80 <HAL_UART_DMAPause>:
 8004d80:	b510      	push	{r4, lr}
 8004d82:	4601      	mov	r1, r0
 8004d84:	2200      	movs	r2, #0
 8004d86:	6808      	ldr	r0, [r1, #0]
 8004d88:	6940      	ldr	r0, [r0, #20]
 8004d8a:	f3c0 12c0 	ubfx	r2, r0, #7, #1
 8004d8e:	f891 0041 	ldrb.w	r0, [r1, #65]	@ 0x41
 8004d92:	2821      	cmp	r0, #33	@ 0x21
 8004d94:	d10f      	bne.n	8004db6 <HAL_UART_DMAPause+0x36>
 8004d96:	b172      	cbz	r2, 8004db6 <HAL_UART_DMAPause+0x36>
 8004d98:	bf00      	nop
 8004d9a:	bf00      	nop
 8004d9c:	680b      	ldr	r3, [r1, #0]
 8004d9e:	3314      	adds	r3, #20
 8004da0:	e853 3f00 	ldrex	r3, [r3]
 8004da4:	f023 0080 	bic.w	r0, r3, #128	@ 0x80
 8004da8:	680b      	ldr	r3, [r1, #0]
 8004daa:	3314      	adds	r3, #20
 8004dac:	e843 0400 	strex	r4, r0, [r3]
 8004db0:	2c00      	cmp	r4, #0
 8004db2:	d1f3      	bne.n	8004d9c <HAL_UART_DMAPause+0x1c>
 8004db4:	bf00      	nop
 8004db6:	6808      	ldr	r0, [r1, #0]
 8004db8:	6940      	ldr	r0, [r0, #20]
 8004dba:	f3c0 1280 	ubfx	r2, r0, #6, #1
 8004dbe:	f891 0042 	ldrb.w	r0, [r1, #66]	@ 0x42
 8004dc2:	2822      	cmp	r0, #34	@ 0x22
 8004dc4:	d12d      	bne.n	8004e22 <HAL_UART_DMAPause+0xa2>
 8004dc6:	b362      	cbz	r2, 8004e22 <HAL_UART_DMAPause+0xa2>
 8004dc8:	bf00      	nop
 8004dca:	bf00      	nop
 8004dcc:	680b      	ldr	r3, [r1, #0]
 8004dce:	330c      	adds	r3, #12
 8004dd0:	e853 3f00 	ldrex	r3, [r3]
 8004dd4:	f423 7080 	bic.w	r0, r3, #256	@ 0x100
 8004dd8:	680b      	ldr	r3, [r1, #0]
 8004dda:	330c      	adds	r3, #12
 8004ddc:	e843 0400 	strex	r4, r0, [r3]
 8004de0:	2c00      	cmp	r4, #0
 8004de2:	d1f3      	bne.n	8004dcc <HAL_UART_DMAPause+0x4c>
 8004de4:	bf00      	nop
 8004de6:	bf00      	nop
 8004de8:	bf00      	nop
 8004dea:	680b      	ldr	r3, [r1, #0]
 8004dec:	3314      	adds	r3, #20
 8004dee:	e853 3f00 	ldrex	r3, [r3]
 8004df2:	f023 0001 	bic.w	r0, r3, #1
 8004df6:	680b      	ldr	r3, [r1, #0]
 8004df8:	3314      	adds	r3, #20
 8004dfa:	e843 0400 	strex	r4, r0, [r3]
 8004dfe:	2c00      	cmp	r4, #0
 8004e00:	d1f3      	bne.n	8004dea <HAL_UART_DMAPause+0x6a>
 8004e02:	bf00      	nop
 8004e04:	bf00      	nop
 8004e06:	bf00      	nop
 8004e08:	680b      	ldr	r3, [r1, #0]
 8004e0a:	3314      	adds	r3, #20
 8004e0c:	e853 3f00 	ldrex	r3, [r3]
 8004e10:	f023 0040 	bic.w	r0, r3, #64	@ 0x40
 8004e14:	680b      	ldr	r3, [r1, #0]
 8004e16:	3314      	adds	r3, #20
 8004e18:	e843 0400 	strex	r4, r0, [r3]
 8004e1c:	2c00      	cmp	r4, #0
 8004e1e:	d1f3      	bne.n	8004e08 <HAL_UART_DMAPause+0x88>
 8004e20:	bf00      	nop
 8004e22:	2000      	movs	r0, #0
 8004e24:	bd10      	pop	{r4, pc}

08004e26 <HAL_UART_DMAResume>:
 8004e26:	b508      	push	{r3, lr}
 8004e28:	4601      	mov	r1, r0
 8004e2a:	f891 0041 	ldrb.w	r0, [r1, #65]	@ 0x41
 8004e2e:	2821      	cmp	r0, #33	@ 0x21
 8004e30:	d10e      	bne.n	8004e50 <HAL_UART_DMAResume+0x2a>
 8004e32:	bf00      	nop
 8004e34:	bf00      	nop
 8004e36:	680a      	ldr	r2, [r1, #0]
 8004e38:	3214      	adds	r2, #20
 8004e3a:	e852 2f00 	ldrex	r2, [r2]
 8004e3e:	f042 0080 	orr.w	r0, r2, #128	@ 0x80
 8004e42:	680a      	ldr	r2, [r1, #0]
 8004e44:	3214      	adds	r2, #20
 8004e46:	e842 0300 	strex	r3, r0, [r2]
 8004e4a:	2b00      	cmp	r3, #0
 8004e4c:	d1f3      	bne.n	8004e36 <HAL_UART_DMAResume+0x10>
 8004e4e:	bf00      	nop
 8004e50:	f891 0042 	ldrb.w	r0, [r1, #66]	@ 0x42
 8004e54:	2822      	cmp	r0, #34	@ 0x22
 8004e56:	d139      	bne.n	8004ecc <HAL_UART_DMAResume+0xa6>
 8004e58:	bf00      	nop
 8004e5a:	2000      	movs	r0, #0
 8004e5c:	9000      	str	r0, [sp, #0]
 8004e5e:	6808      	ldr	r0, [r1, #0]
 8004e60:	6800      	ldr	r0, [r0, #0]
 8004e62:	9000      	str	r0, [sp, #0]
 8004e64:	6808      	ldr	r0, [r1, #0]
 8004e66:	6840      	ldr	r0, [r0, #4]
 8004e68:	9000      	str	r0, [sp, #0]
 8004e6a:	bf00      	nop
 8004e6c:	bf00      	nop
 8004e6e:	6908      	ldr	r0, [r1, #16]
 8004e70:	b170      	cbz	r0, 8004e90 <HAL_UART_DMAResume+0x6a>
 8004e72:	bf00      	nop
 8004e74:	bf00      	nop
 8004e76:	680a      	ldr	r2, [r1, #0]
 8004e78:	320c      	adds	r2, #12
 8004e7a:	e852 2f00 	ldrex	r2, [r2]
 8004e7e:	f442 7080 	orr.w	r0, r2, #256	@ 0x100
 8004e82:	680a      	ldr	r2, [r1, #0]
 8004e84:	320c      	adds	r2, #12
 8004e86:	e842 0300 	strex	r3, r0, [r2]
 8004e8a:	2b00      	cmp	r3, #0
 8004e8c:	d1f3      	bne.n	8004e76 <HAL_UART_DMAResume+0x50>
 8004e8e:	bf00      	nop
 8004e90:	bf00      	nop
 8004e92:	bf00      	nop
 8004e94:	680a      	ldr	r2, [r1, #0]
 8004e96:	3214      	adds	r2, #20
 8004e98:	e852 2f00 	ldrex	r2, [r2]
 8004e9c:	f042 0001 	orr.w	r0, r2, #1
 8004ea0:	680a      	ldr	r2, [r1, #0]
 8004ea2:	3214      	adds	r2, #20
 8004ea4:	e842 0300 	strex	r3, r0, [r2]
 8004ea8:	2b00      	cmp	r3, #0
 8004eaa:	d1f3      	bne.n	8004e94 <HAL_UART_DMAResume+0x6e>
 8004eac:	bf00      	nop
 8004eae:	bf00      	nop
 8004eb0:	bf00      	nop
 8004eb2:	680a      	ldr	r2, [r1, #0]
 8004eb4:	3214      	adds	r2, #20
 8004eb6:	e852 2f00 	ldrex	r2, [r2]
 8004eba:	f042 0040 	orr.w	r0, r2, #64	@ 0x40
 8004ebe:	680a      	ldr	r2, [r1, #0]
 8004ec0:	3214      	adds	r2, #20
 8004ec2:	e842 0300 	strex	r3, r0, [r2]
 8004ec6:	2b00      	cmp	r3, #0
 8004ec8:	d1f3      	bne.n	8004eb2 <HAL_UART_DMAResume+0x8c>
 8004eca:	bf00      	nop
 8004ecc:	2000      	movs	r0, #0
 8004ece:	bd08      	pop	{r3, pc}

08004ed0 <HAL_UART_DMAStop>:
 8004ed0:	b570      	push	{r4, r5, r6, lr}
 8004ed2:	4604      	mov	r4, r0
 8004ed4:	2500      	movs	r5, #0
 8004ed6:	6820      	ldr	r0, [r4, #0]
 8004ed8:	6940      	ldr	r0, [r0, #20]
 8004eda:	f3c0 15c0 	ubfx	r5, r0, #7, #1
 8004ede:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 8004ee2:	2821      	cmp	r0, #33	@ 0x21
 8004ee4:	d117      	bne.n	8004f16 <HAL_UART_DMAStop+0x46>
 8004ee6:	b1b5      	cbz	r5, 8004f16 <HAL_UART_DMAStop+0x46>
 8004ee8:	bf00      	nop
 8004eea:	bf00      	nop
 8004eec:	6821      	ldr	r1, [r4, #0]
 8004eee:	3114      	adds	r1, #20
 8004ef0:	e851 1f00 	ldrex	r1, [r1]
 8004ef4:	f021 0080 	bic.w	r0, r1, #128	@ 0x80
 8004ef8:	6821      	ldr	r1, [r4, #0]
 8004efa:	3114      	adds	r1, #20
 8004efc:	e841 0200 	strex	r2, r0, [r1]
 8004f00:	2a00      	cmp	r2, #0
 8004f02:	d1f3      	bne.n	8004eec <HAL_UART_DMAStop+0x1c>
 8004f04:	bf00      	nop
 8004f06:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004f08:	b110      	cbz	r0, 8004f10 <HAL_UART_DMAStop+0x40>
 8004f0a:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8004f0c:	f7fc fa3c 	bl	8001388 <HAL_DMA_Abort>
 8004f10:	4620      	mov	r0, r4
 8004f12:	f000 fe09 	bl	8005b28 <UART_EndTxTransfer>
 8004f16:	6820      	ldr	r0, [r4, #0]
 8004f18:	6940      	ldr	r0, [r0, #20]
 8004f1a:	f3c0 1580 	ubfx	r5, r0, #6, #1
 8004f1e:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 8004f22:	2822      	cmp	r0, #34	@ 0x22
 8004f24:	d117      	bne.n	8004f56 <HAL_UART_DMAStop+0x86>
 8004f26:	b1b5      	cbz	r5, 8004f56 <HAL_UART_DMAStop+0x86>
 8004f28:	bf00      	nop
 8004f2a:	bf00      	nop
 8004f2c:	6821      	ldr	r1, [r4, #0]
 8004f2e:	3114      	adds	r1, #20
 8004f30:	e851 1f00 	ldrex	r1, [r1]
 8004f34:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 8004f38:	6821      	ldr	r1, [r4, #0]
 8004f3a:	3114      	adds	r1, #20
 8004f3c:	e841 0200 	strex	r2, r0, [r1]
 8004f40:	2a00      	cmp	r2, #0
 8004f42:	d1f3      	bne.n	8004f2c <HAL_UART_DMAStop+0x5c>
 8004f44:	bf00      	nop
 8004f46:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004f48:	b110      	cbz	r0, 8004f50 <HAL_UART_DMAStop+0x80>
 8004f4a:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8004f4c:	f7fc fa1c 	bl	8001388 <HAL_DMA_Abort>
 8004f50:	4620      	mov	r0, r4
 8004f52:	f000 fda3 	bl	8005a9c <UART_EndRxTransfer>
 8004f56:	2000      	movs	r0, #0
 8004f58:	bd70      	pop	{r4, r5, r6, pc}

08004f5a <HAL_UART_DeInit>:
 8004f5a:	b510      	push	{r4, lr}
 8004f5c:	4604      	mov	r4, r0
 8004f5e:	b90c      	cbnz	r4, 8004f64 <HAL_UART_DeInit+0xa>
 8004f60:	2001      	movs	r0, #1
 8004f62:	bd10      	pop	{r4, pc}
 8004f64:	2024      	movs	r0, #36	@ 0x24
 8004f66:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8004f6a:	6820      	ldr	r0, [r4, #0]
 8004f6c:	68c0      	ldr	r0, [r0, #12]
 8004f6e:	f420 5000 	bic.w	r0, r0, #8192	@ 0x2000
 8004f72:	6821      	ldr	r1, [r4, #0]
 8004f74:	60c8      	str	r0, [r1, #12]
 8004f76:	4620      	mov	r0, r4
 8004f78:	f000 f9ca 	bl	8005310 <HAL_UART_MspDeInit>
 8004f7c:	2000      	movs	r0, #0
 8004f7e:	6460      	str	r0, [r4, #68]	@ 0x44
 8004f80:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8004f84:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8004f88:	6320      	str	r0, [r4, #48]	@ 0x30
 8004f8a:	6360      	str	r0, [r4, #52]	@ 0x34
 8004f8c:	bf00      	nop
 8004f8e:	f884 0040 	strb.w	r0, [r4, #64]	@ 0x40
 8004f92:	bf00      	nop
 8004f94:	bf00      	nop
 8004f96:	e7e4      	b.n	8004f62 <HAL_UART_DeInit+0x8>

08004f98 <HAL_UART_ErrorCallback>:
 8004f98:	4770      	bx	lr

08004f9a <HAL_UART_GetError>:
 8004f9a:	4601      	mov	r1, r0
 8004f9c:	6c48      	ldr	r0, [r1, #68]	@ 0x44
 8004f9e:	4770      	bx	lr

08004fa0 <HAL_UART_GetState>:
 8004fa0:	4601      	mov	r1, r0
 8004fa2:	2200      	movs	r2, #0
 8004fa4:	2300      	movs	r3, #0
 8004fa6:	f891 2041 	ldrb.w	r2, [r1, #65]	@ 0x41
 8004faa:	f891 3042 	ldrb.w	r3, [r1, #66]	@ 0x42
 8004fae:	ea42 0003 	orr.w	r0, r2, r3
 8004fb2:	4770      	bx	lr

08004fb4 <HAL_UART_IRQHandler>:
 8004fb4:	e92d 4ff8 	stmdb	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
 8004fb8:	4604      	mov	r4, r0
 8004fba:	6820      	ldr	r0, [r4, #0]
 8004fbc:	6805      	ldr	r5, [r0, #0]
 8004fbe:	6820      	ldr	r0, [r4, #0]
 8004fc0:	68c6      	ldr	r6, [r0, #12]
 8004fc2:	6820      	ldr	r0, [r4, #0]
 8004fc4:	6947      	ldr	r7, [r0, #20]
 8004fc6:	f04f 0900 	mov.w	r9, #0
 8004fca:	46ca      	mov	sl, r9
 8004fcc:	f005 090f 	and.w	r9, r5, #15
 8004fd0:	f1b9 0f00 	cmp.w	r9, #0
 8004fd4:	d10a      	bne.n	8004fec <HAL_UART_IRQHandler+0x38>
 8004fd6:	f005 0020 	and.w	r0, r5, #32
 8004fda:	b138      	cbz	r0, 8004fec <HAL_UART_IRQHandler+0x38>
 8004fdc:	f006 0020 	and.w	r0, r6, #32
 8004fe0:	b120      	cbz	r0, 8004fec <HAL_UART_IRQHandler+0x38>
 8004fe2:	4620      	mov	r0, r4
 8004fe4:	f000 fdb3 	bl	8005b4e <UART_Receive_IT>
 8004fe8:	e8bd 8ff8 	ldmia.w	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, pc}
 8004fec:	f1b9 0f00 	cmp.w	r9, #0
 8004ff0:	d07b      	beq.n	80050ea <HAL_UART_IRQHandler+0x136>
 8004ff2:	f007 0001 	and.w	r0, r7, #1
 8004ff6:	b918      	cbnz	r0, 8005000 <HAL_UART_IRQHandler+0x4c>
 8004ff8:	f406 7090 	and.w	r0, r6, #288	@ 0x120
 8004ffc:	2800      	cmp	r0, #0
 8004ffe:	d074      	beq.n	80050ea <HAL_UART_IRQHandler+0x136>
 8005000:	f005 0001 	and.w	r0, r5, #1
 8005004:	b130      	cbz	r0, 8005014 <HAL_UART_IRQHandler+0x60>
 8005006:	f406 7080 	and.w	r0, r6, #256	@ 0x100
 800500a:	b118      	cbz	r0, 8005014 <HAL_UART_IRQHandler+0x60>
 800500c:	6c60      	ldr	r0, [r4, #68]	@ 0x44
 800500e:	f040 0001 	orr.w	r0, r0, #1
 8005012:	6460      	str	r0, [r4, #68]	@ 0x44
 8005014:	f005 0004 	and.w	r0, r5, #4
 8005018:	b130      	cbz	r0, 8005028 <HAL_UART_IRQHandler+0x74>
 800501a:	f007 0001 	and.w	r0, r7, #1
 800501e:	b118      	cbz	r0, 8005028 <HAL_UART_IRQHandler+0x74>
 8005020:	6c60      	ldr	r0, [r4, #68]	@ 0x44
 8005022:	f040 0002 	orr.w	r0, r0, #2
 8005026:	6460      	str	r0, [r4, #68]	@ 0x44
 8005028:	f005 0002 	and.w	r0, r5, #2
 800502c:	b130      	cbz	r0, 800503c <HAL_UART_IRQHandler+0x88>
 800502e:	f007 0001 	and.w	r0, r7, #1
 8005032:	b118      	cbz	r0, 800503c <HAL_UART_IRQHandler+0x88>
 8005034:	6c60      	ldr	r0, [r4, #68]	@ 0x44
 8005036:	f040 0004 	orr.w	r0, r0, #4
 800503a:	6460      	str	r0, [r4, #68]	@ 0x44
 800503c:	f005 0008 	and.w	r0, r5, #8
 8005040:	b148      	cbz	r0, 8005056 <HAL_UART_IRQHandler+0xa2>
 8005042:	f006 0020 	and.w	r0, r6, #32
 8005046:	b910      	cbnz	r0, 800504e <HAL_UART_IRQHandler+0x9a>
 8005048:	f007 0001 	and.w	r0, r7, #1
 800504c:	b118      	cbz	r0, 8005056 <HAL_UART_IRQHandler+0xa2>
 800504e:	6c60      	ldr	r0, [r4, #68]	@ 0x44
 8005050:	f040 0008 	orr.w	r0, r0, #8
 8005054:	6460      	str	r0, [r4, #68]	@ 0x44
 8005056:	6c60      	ldr	r0, [r4, #68]	@ 0x44
 8005058:	2800      	cmp	r0, #0
 800505a:	d045      	beq.n	80050e8 <HAL_UART_IRQHandler+0x134>
 800505c:	f005 0020 	and.w	r0, r5, #32
 8005060:	b128      	cbz	r0, 800506e <HAL_UART_IRQHandler+0xba>
 8005062:	f006 0020 	and.w	r0, r6, #32
 8005066:	b110      	cbz	r0, 800506e <HAL_UART_IRQHandler+0xba>
 8005068:	4620      	mov	r0, r4
 800506a:	f000 fd70 	bl	8005b4e <UART_Receive_IT>
 800506e:	6820      	ldr	r0, [r4, #0]
 8005070:	6940      	ldr	r0, [r0, #20]
 8005072:	f3c0 1a80 	ubfx	sl, r0, #6, #1
 8005076:	6c60      	ldr	r0, [r4, #68]	@ 0x44
 8005078:	f000 0008 	and.w	r0, r0, #8
 800507c:	b910      	cbnz	r0, 8005084 <HAL_UART_IRQHandler+0xd0>
 800507e:	f1ba 0f00 	cmp.w	sl, #0
 8005082:	d02c      	beq.n	80050de <HAL_UART_IRQHandler+0x12a>
 8005084:	4620      	mov	r0, r4
 8005086:	f000 fd09 	bl	8005a9c <UART_EndRxTransfer>
 800508a:	6820      	ldr	r0, [r4, #0]
 800508c:	6940      	ldr	r0, [r0, #20]
 800508e:	f000 0040 	and.w	r0, r0, #64	@ 0x40
 8005092:	b300      	cbz	r0, 80050d6 <HAL_UART_IRQHandler+0x122>
 8005094:	bf00      	nop
 8005096:	bf00      	nop
 8005098:	6821      	ldr	r1, [r4, #0]
 800509a:	3114      	adds	r1, #20
 800509c:	e851 1f00 	ldrex	r1, [r1]
 80050a0:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 80050a4:	6821      	ldr	r1, [r4, #0]
 80050a6:	3114      	adds	r1, #20
 80050a8:	e841 0200 	strex	r2, r0, [r1]
 80050ac:	2a00      	cmp	r2, #0
 80050ae:	d1f3      	bne.n	8005098 <HAL_UART_IRQHandler+0xe4>
 80050b0:	bf00      	nop
 80050b2:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 80050b4:	b150      	cbz	r0, 80050cc <HAL_UART_IRQHandler+0x118>
 80050b6:	4877      	ldr	r0, [pc, #476]	@ (8005294 <HAL_UART_IRQHandler+0x2e0>)
 80050b8:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 80050ba:	6348      	str	r0, [r1, #52]	@ 0x34
 80050bc:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 80050be:	f7fc f98f 	bl	80013e0 <HAL_DMA_Abort_IT>
 80050c2:	b188      	cbz	r0, 80050e8 <HAL_UART_IRQHandler+0x134>
 80050c4:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 80050c6:	6b41      	ldr	r1, [r0, #52]	@ 0x34
 80050c8:	4788      	blx	r1
 80050ca:	e00d      	b.n	80050e8 <HAL_UART_IRQHandler+0x134>
 80050cc:	4620      	mov	r0, r4
 80050ce:	f7ff ff63 	bl	8004f98 <HAL_UART_ErrorCallback>
 80050d2:	e009      	b.n	80050e8 <HAL_UART_IRQHandler+0x134>
 80050d4:	e009      	b.n	80050ea <HAL_UART_IRQHandler+0x136>
 80050d6:	4620      	mov	r0, r4
 80050d8:	f7ff ff5e 	bl	8004f98 <HAL_UART_ErrorCallback>
 80050dc:	e004      	b.n	80050e8 <HAL_UART_IRQHandler+0x134>
 80050de:	4620      	mov	r0, r4
 80050e0:	f7ff ff5a 	bl	8004f98 <HAL_UART_ErrorCallback>
 80050e4:	2000      	movs	r0, #0
 80050e6:	6460      	str	r0, [r4, #68]	@ 0x44
 80050e8:	e77e      	b.n	8004fe8 <HAL_UART_IRQHandler+0x34>
 80050ea:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 80050ec:	2801      	cmp	r0, #1
 80050ee:	d177      	bne.n	80051e0 <HAL_UART_IRQHandler+0x22c>
 80050f0:	f005 0010 	and.w	r0, r5, #16
 80050f4:	2800      	cmp	r0, #0
 80050f6:	d073      	beq.n	80051e0 <HAL_UART_IRQHandler+0x22c>
 80050f8:	f006 0010 	and.w	r0, r6, #16
 80050fc:	2800      	cmp	r0, #0
 80050fe:	d0fa      	beq.n	80050f6 <HAL_UART_IRQHandler+0x142>
 8005100:	bf00      	nop
 8005102:	2000      	movs	r0, #0
 8005104:	9000      	str	r0, [sp, #0]
 8005106:	6820      	ldr	r0, [r4, #0]
 8005108:	6800      	ldr	r0, [r0, #0]
 800510a:	9000      	str	r0, [sp, #0]
 800510c:	6820      	ldr	r0, [r4, #0]
 800510e:	6840      	ldr	r0, [r0, #4]
 8005110:	9000      	str	r0, [sp, #0]
 8005112:	bf00      	nop
 8005114:	bf00      	nop
 8005116:	6820      	ldr	r0, [r4, #0]
 8005118:	6940      	ldr	r0, [r0, #20]
 800511a:	f000 0040 	and.w	r0, r0, #64	@ 0x40
 800511e:	2800      	cmp	r0, #0
 8005120:	d05f      	beq.n	80051e2 <HAL_UART_IRQHandler+0x22e>
 8005122:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8005124:	6800      	ldr	r0, [r0, #0]
 8005126:	6840      	ldr	r0, [r0, #4]
 8005128:	fa1f f880 	uxth.w	r8, r0
 800512c:	f1b8 0f00 	cmp.w	r8, #0
 8005130:	d055      	beq.n	80051de <HAL_UART_IRQHandler+0x22a>
 8005132:	8da0      	ldrh	r0, [r4, #44]	@ 0x2c
 8005134:	4540      	cmp	r0, r8
 8005136:	dd52      	ble.n	80051de <HAL_UART_IRQHandler+0x22a>
 8005138:	f8a4 802e 	strh.w	r8, [r4, #46]	@ 0x2e
 800513c:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 800513e:	6980      	ldr	r0, [r0, #24]
 8005140:	2820      	cmp	r0, #32
 8005142:	d043      	beq.n	80051cc <HAL_UART_IRQHandler+0x218>
 8005144:	bf00      	nop
 8005146:	bf00      	nop
 8005148:	6821      	ldr	r1, [r4, #0]
 800514a:	310c      	adds	r1, #12
 800514c:	e851 1f00 	ldrex	r1, [r1]
 8005150:	f421 7080 	bic.w	r0, r1, #256	@ 0x100
 8005154:	6821      	ldr	r1, [r4, #0]
 8005156:	310c      	adds	r1, #12
 8005158:	e841 0200 	strex	r2, r0, [r1]
 800515c:	2a00      	cmp	r2, #0
 800515e:	d1f3      	bne.n	8005148 <HAL_UART_IRQHandler+0x194>
 8005160:	bf00      	nop
 8005162:	bf00      	nop
 8005164:	bf00      	nop
 8005166:	6821      	ldr	r1, [r4, #0]
 8005168:	3114      	adds	r1, #20
 800516a:	e851 1f00 	ldrex	r1, [r1]
 800516e:	f021 0001 	bic.w	r0, r1, #1
 8005172:	6821      	ldr	r1, [r4, #0]
 8005174:	3114      	adds	r1, #20
 8005176:	e841 0200 	strex	r2, r0, [r1]
 800517a:	2a00      	cmp	r2, #0
 800517c:	d1f3      	bne.n	8005166 <HAL_UART_IRQHandler+0x1b2>
 800517e:	bf00      	nop
 8005180:	bf00      	nop
 8005182:	bf00      	nop
 8005184:	6821      	ldr	r1, [r4, #0]
 8005186:	3114      	adds	r1, #20
 8005188:	e851 1f00 	ldrex	r1, [r1]
 800518c:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 8005190:	6821      	ldr	r1, [r4, #0]
 8005192:	3114      	adds	r1, #20
 8005194:	e841 0200 	strex	r2, r0, [r1]
 8005198:	2a00      	cmp	r2, #0
 800519a:	d1f3      	bne.n	8005184 <HAL_UART_IRQHandler+0x1d0>
 800519c:	bf00      	nop
 800519e:	2020      	movs	r0, #32
 80051a0:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 80051a4:	2000      	movs	r0, #0
 80051a6:	6320      	str	r0, [r4, #48]	@ 0x30
 80051a8:	bf00      	nop
 80051aa:	bf00      	nop
 80051ac:	6821      	ldr	r1, [r4, #0]
 80051ae:	310c      	adds	r1, #12
 80051b0:	e851 1f00 	ldrex	r1, [r1]
 80051b4:	f021 0010 	bic.w	r0, r1, #16
 80051b8:	6821      	ldr	r1, [r4, #0]
 80051ba:	310c      	adds	r1, #12
 80051bc:	e841 0200 	strex	r2, r0, [r1]
 80051c0:	2a00      	cmp	r2, #0
 80051c2:	d1f3      	bne.n	80051ac <HAL_UART_IRQHandler+0x1f8>
 80051c4:	bf00      	nop
 80051c6:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 80051c8:	f7fc f8de 	bl	8001388 <HAL_DMA_Abort>
 80051cc:	2002      	movs	r0, #2
 80051ce:	6360      	str	r0, [r4, #52]	@ 0x34
 80051d0:	8da0      	ldrh	r0, [r4, #44]	@ 0x2c
 80051d2:	8de2      	ldrh	r2, [r4, #46]	@ 0x2e
 80051d4:	1a80      	subs	r0, r0, r2
 80051d6:	b281      	uxth	r1, r0
 80051d8:	4620      	mov	r0, r4
 80051da:	f7ff fb4a 	bl	8004872 <HAL_UARTEx_RxEventCallback>
 80051de:	e703      	b.n	8004fe8 <HAL_UART_IRQHandler+0x34>
 80051e0:	e042      	b.n	8005268 <HAL_UART_IRQHandler+0x2b4>
 80051e2:	8da0      	ldrh	r0, [r4, #44]	@ 0x2c
 80051e4:	8de1      	ldrh	r1, [r4, #46]	@ 0x2e
 80051e6:	1a40      	subs	r0, r0, r1
 80051e8:	fa1f f880 	uxth.w	r8, r0
 80051ec:	8de0      	ldrh	r0, [r4, #46]	@ 0x2e
 80051ee:	b3d0      	cbz	r0, 8005266 <HAL_UART_IRQHandler+0x2b2>
 80051f0:	f1b8 0f00 	cmp.w	r8, #0
 80051f4:	d037      	beq.n	8005266 <HAL_UART_IRQHandler+0x2b2>
 80051f6:	bf00      	nop
 80051f8:	bf00      	nop
 80051fa:	6821      	ldr	r1, [r4, #0]
 80051fc:	310c      	adds	r1, #12
 80051fe:	e851 1f00 	ldrex	r1, [r1]
 8005202:	f421 7090 	bic.w	r0, r1, #288	@ 0x120
 8005206:	6821      	ldr	r1, [r4, #0]
 8005208:	310c      	adds	r1, #12
 800520a:	e841 0200 	strex	r2, r0, [r1]
 800520e:	2a00      	cmp	r2, #0
 8005210:	d1f3      	bne.n	80051fa <HAL_UART_IRQHandler+0x246>
 8005212:	bf00      	nop
 8005214:	bf00      	nop
 8005216:	bf00      	nop
 8005218:	6821      	ldr	r1, [r4, #0]
 800521a:	3114      	adds	r1, #20
 800521c:	e851 1f00 	ldrex	r1, [r1]
 8005220:	f021 0001 	bic.w	r0, r1, #1
 8005224:	6821      	ldr	r1, [r4, #0]
 8005226:	3114      	adds	r1, #20
 8005228:	e841 0200 	strex	r2, r0, [r1]
 800522c:	2a00      	cmp	r2, #0
 800522e:	d1f3      	bne.n	8005218 <HAL_UART_IRQHandler+0x264>
 8005230:	bf00      	nop
 8005232:	2020      	movs	r0, #32
 8005234:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8005238:	2000      	movs	r0, #0
 800523a:	6320      	str	r0, [r4, #48]	@ 0x30
 800523c:	bf00      	nop
 800523e:	bf00      	nop
 8005240:	6821      	ldr	r1, [r4, #0]
 8005242:	310c      	adds	r1, #12
 8005244:	e851 1f00 	ldrex	r1, [r1]
 8005248:	f021 0010 	bic.w	r0, r1, #16
 800524c:	6821      	ldr	r1, [r4, #0]
 800524e:	310c      	adds	r1, #12
 8005250:	e841 0200 	strex	r2, r0, [r1]
 8005254:	2a00      	cmp	r2, #0
 8005256:	d1f3      	bne.n	8005240 <HAL_UART_IRQHandler+0x28c>
 8005258:	bf00      	nop
 800525a:	2002      	movs	r0, #2
 800525c:	6360      	str	r0, [r4, #52]	@ 0x34
 800525e:	4641      	mov	r1, r8
 8005260:	4620      	mov	r0, r4
 8005262:	f7ff fb06 	bl	8004872 <HAL_UARTEx_RxEventCallback>
 8005266:	e6bf      	b.n	8004fe8 <HAL_UART_IRQHandler+0x34>
 8005268:	f005 0080 	and.w	r0, r5, #128	@ 0x80
 800526c:	b130      	cbz	r0, 800527c <HAL_UART_IRQHandler+0x2c8>
 800526e:	f006 0080 	and.w	r0, r6, #128	@ 0x80
 8005272:	b118      	cbz	r0, 800527c <HAL_UART_IRQHandler+0x2c8>
 8005274:	4620      	mov	r0, r4
 8005276:	f000 fdeb 	bl	8005e50 <UART_Transmit_IT>
 800527a:	e6b5      	b.n	8004fe8 <HAL_UART_IRQHandler+0x34>
 800527c:	f005 0040 	and.w	r0, r5, #64	@ 0x40
 8005280:	b130      	cbz	r0, 8005290 <HAL_UART_IRQHandler+0x2dc>
 8005282:	f006 0040 	and.w	r0, r6, #64	@ 0x40
 8005286:	b118      	cbz	r0, 8005290 <HAL_UART_IRQHandler+0x2dc>
 8005288:	4620      	mov	r0, r4
 800528a:	f000 fc3d 	bl	8005b08 <UART_EndTransmit_IT>
 800528e:	e6ab      	b.n	8004fe8 <HAL_UART_IRQHandler+0x34>
 8005290:	bf00      	nop
 8005292:	e6a9      	b.n	8004fe8 <HAL_UART_IRQHandler+0x34>
 8005294:	08005857 	.word	0x08005857

08005298 <HAL_UART_Init>:
 8005298:	b510      	push	{r4, lr}
 800529a:	4604      	mov	r4, r0
 800529c:	b90c      	cbnz	r4, 80052a2 <HAL_UART_Init+0xa>
 800529e:	2001      	movs	r0, #1
 80052a0:	bd10      	pop	{r4, pc}
 80052a2:	69a0      	ldr	r0, [r4, #24]
 80052a4:	b100      	cbz	r0, 80052a8 <HAL_UART_Init+0x10>
 80052a6:	e000      	b.n	80052aa <HAL_UART_Init+0x12>
 80052a8:	bf00      	nop
 80052aa:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 80052ae:	b928      	cbnz	r0, 80052bc <HAL_UART_Init+0x24>
 80052b0:	2000      	movs	r0, #0
 80052b2:	f884 0040 	strb.w	r0, [r4, #64]	@ 0x40
 80052b6:	4620      	mov	r0, r4
 80052b8:	f000 f844 	bl	8005344 <HAL_UART_MspInit>
 80052bc:	2024      	movs	r0, #36	@ 0x24
 80052be:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 80052c2:	6820      	ldr	r0, [r4, #0]
 80052c4:	68c0      	ldr	r0, [r0, #12]
 80052c6:	f420 5000 	bic.w	r0, r0, #8192	@ 0x2000
 80052ca:	6821      	ldr	r1, [r4, #0]
 80052cc:	60c8      	str	r0, [r1, #12]
 80052ce:	4620      	mov	r0, r4
 80052d0:	f000 fcbc 	bl	8005c4c <UART_SetConfig>
 80052d4:	6820      	ldr	r0, [r4, #0]
 80052d6:	6900      	ldr	r0, [r0, #16]
 80052d8:	f420 4090 	bic.w	r0, r0, #18432	@ 0x4800
 80052dc:	6821      	ldr	r1, [r4, #0]
 80052de:	6108      	str	r0, [r1, #16]
 80052e0:	6820      	ldr	r0, [r4, #0]
 80052e2:	6940      	ldr	r0, [r0, #20]
 80052e4:	f020 002a 	bic.w	r0, r0, #42	@ 0x2a
 80052e8:	6821      	ldr	r1, [r4, #0]
 80052ea:	6148      	str	r0, [r1, #20]
 80052ec:	6820      	ldr	r0, [r4, #0]
 80052ee:	68c0      	ldr	r0, [r0, #12]
 80052f0:	f440 5000 	orr.w	r0, r0, #8192	@ 0x2000
 80052f4:	6821      	ldr	r1, [r4, #0]
 80052f6:	60c8      	str	r0, [r1, #12]
 80052f8:	2000      	movs	r0, #0
 80052fa:	6460      	str	r0, [r4, #68]	@ 0x44
 80052fc:	2020      	movs	r0, #32
 80052fe:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005302:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8005306:	2000      	movs	r0, #0
 8005308:	6360      	str	r0, [r4, #52]	@ 0x34
 800530a:	bf00      	nop
 800530c:	e7c8      	b.n	80052a0 <HAL_UART_Init+0x8>
	...

08005310 <HAL_UART_MspDeInit>:
 8005310:	b510      	push	{r4, lr}
 8005312:	4604      	mov	r4, r0
 8005314:	4907      	ldr	r1, [pc, #28]	@ (8005334 <HAL_UART_MspDeInit+0x24>)
 8005316:	6820      	ldr	r0, [r4, #0]
 8005318:	4288      	cmp	r0, r1
 800531a:	d10a      	bne.n	8005332 <HAL_UART_MspDeInit+0x22>
 800531c:	4806      	ldr	r0, [pc, #24]	@ (8005338 <HAL_UART_MspDeInit+0x28>)
 800531e:	6980      	ldr	r0, [r0, #24]
 8005320:	f420 4080 	bic.w	r0, r0, #16384	@ 0x4000
 8005324:	4904      	ldr	r1, [pc, #16]	@ (8005338 <HAL_UART_MspDeInit+0x28>)
 8005326:	6188      	str	r0, [r1, #24]
 8005328:	f44f 61c0 	mov.w	r1, #1536	@ 0x600
 800532c:	4803      	ldr	r0, [pc, #12]	@ (800533c <HAL_UART_MspDeInit+0x2c>)
 800532e:	f7fd fc07 	bl	8002b40 <HAL_GPIO_DeInit>
 8005332:	bd10      	pop	{r4, pc}
 8005334:	40013800 	.word	0x40013800
 8005338:	40021000 	.word	0x40021000
 800533c:	40010800 	.word	0x40010800
 8005340:	4770      	bx	lr
	...

08005344 <HAL_UART_MspInit>:
 8005344:	b510      	push	{r4, lr}
 8005346:	b086      	sub	sp, #24
 8005348:	4604      	mov	r4, r0
 800534a:	2000      	movs	r0, #0
 800534c:	9002      	str	r0, [sp, #8]
 800534e:	9003      	str	r0, [sp, #12]
 8005350:	9004      	str	r0, [sp, #16]
 8005352:	9005      	str	r0, [sp, #20]
 8005354:	491a      	ldr	r1, [pc, #104]	@ (80053c0 <HAL_UART_MspInit+0x7c>)
 8005356:	6820      	ldr	r0, [r4, #0]
 8005358:	4288      	cmp	r0, r1
 800535a:	d12e      	bne.n	80053ba <HAL_UART_MspInit+0x76>
 800535c:	bf00      	nop
 800535e:	4819      	ldr	r0, [pc, #100]	@ (80053c4 <HAL_UART_MspInit+0x80>)
 8005360:	6980      	ldr	r0, [r0, #24]
 8005362:	f440 4080 	orr.w	r0, r0, #16384	@ 0x4000
 8005366:	4917      	ldr	r1, [pc, #92]	@ (80053c4 <HAL_UART_MspInit+0x80>)
 8005368:	6188      	str	r0, [r1, #24]
 800536a:	4608      	mov	r0, r1
 800536c:	6980      	ldr	r0, [r0, #24]
 800536e:	f400 4080 	and.w	r0, r0, #16384	@ 0x4000
 8005372:	9001      	str	r0, [sp, #4]
 8005374:	bf00      	nop
 8005376:	bf00      	nop
 8005378:	bf00      	nop
 800537a:	4608      	mov	r0, r1
 800537c:	6980      	ldr	r0, [r0, #24]
 800537e:	f040 0004 	orr.w	r0, r0, #4
 8005382:	6188      	str	r0, [r1, #24]
 8005384:	4608      	mov	r0, r1
 8005386:	6980      	ldr	r0, [r0, #24]
 8005388:	f000 0004 	and.w	r0, r0, #4
 800538c:	9001      	str	r0, [sp, #4]
 800538e:	bf00      	nop
 8005390:	bf00      	nop
 8005392:	1548      	asrs	r0, r1, #21
 8005394:	9002      	str	r0, [sp, #8]
 8005396:	2002      	movs	r0, #2
 8005398:	9003      	str	r0, [sp, #12]
 800539a:	2003      	movs	r0, #3
 800539c:	9005      	str	r0, [sp, #20]
 800539e:	a902      	add	r1, sp, #8
 80053a0:	4809      	ldr	r0, [pc, #36]	@ (80053c8 <HAL_UART_MspInit+0x84>)
 80053a2:	f7fd fc87 	bl	8002cb4 <HAL_GPIO_Init>
 80053a6:	f44f 6080 	mov.w	r0, #1024	@ 0x400
 80053aa:	9002      	str	r0, [sp, #8]
 80053ac:	2000      	movs	r0, #0
 80053ae:	9003      	str	r0, [sp, #12]
 80053b0:	9004      	str	r0, [sp, #16]
 80053b2:	a902      	add	r1, sp, #8
 80053b4:	4804      	ldr	r0, [pc, #16]	@ (80053c8 <HAL_UART_MspInit+0x84>)
 80053b6:	f7fd fc7d 	bl	8002cb4 <HAL_GPIO_Init>
 80053ba:	b006      	add	sp, #24
 80053bc:	bd10      	pop	{r4, pc}
 80053be:	0000      	.short	0x0000
 80053c0:	40013800 	.word	0x40013800
 80053c4:	40021000 	.word	0x40021000
 80053c8:	40010800 	.word	0x40010800
 80053cc:	4770      	bx	lr

080053ce <HAL_UART_Receive>:
 80053ce:	e92d 4ff8 	stmdb	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
 80053d2:	4604      	mov	r4, r0
 80053d4:	460e      	mov	r6, r1
 80053d6:	4617      	mov	r7, r2
 80053d8:	4699      	mov	r9, r3
 80053da:	f04f 0a00 	mov.w	sl, #0
 80053de:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 80053e2:	2820      	cmp	r0, #32
 80053e4:	d152      	bne.n	800548c <HAL_UART_Receive+0xbe>
 80053e6:	b106      	cbz	r6, 80053ea <HAL_UART_Receive+0x1c>
 80053e8:	b917      	cbnz	r7, 80053f0 <HAL_UART_Receive+0x22>
 80053ea:	2001      	movs	r0, #1
 80053ec:	e8bd 8ff8 	ldmia.w	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, pc}
 80053f0:	2000      	movs	r0, #0
 80053f2:	6460      	str	r0, [r4, #68]	@ 0x44
 80053f4:	2022      	movs	r0, #34	@ 0x22
 80053f6:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 80053fa:	2000      	movs	r0, #0
 80053fc:	6320      	str	r0, [r4, #48]	@ 0x30
 80053fe:	f7fd fe3b 	bl	8003078 <HAL_GetTick>
 8005402:	4682      	mov	sl, r0
 8005404:	85a7      	strh	r7, [r4, #44]	@ 0x2c
 8005406:	85e7      	strh	r7, [r4, #46]	@ 0x2e
 8005408:	68a0      	ldr	r0, [r4, #8]
 800540a:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 800540e:	d104      	bne.n	800541a <HAL_UART_Receive+0x4c>
 8005410:	6920      	ldr	r0, [r4, #16]
 8005412:	b910      	cbnz	r0, 800541a <HAL_UART_Receive+0x4c>
 8005414:	2500      	movs	r5, #0
 8005416:	46b0      	mov	r8, r6
 8005418:	e002      	b.n	8005420 <HAL_UART_Receive+0x52>
 800541a:	4635      	mov	r5, r6
 800541c:	f04f 0800 	mov.w	r8, #0
 8005420:	e02c      	b.n	800547c <HAL_UART_Receive+0xae>
 8005422:	4653      	mov	r3, sl
 8005424:	2200      	movs	r2, #0
 8005426:	2120      	movs	r1, #32
 8005428:	4620      	mov	r0, r4
 800542a:	f8cd 9000 	str.w	r9, [sp]
 800542e:	f000 fd3f 	bl	8005eb0 <UART_WaitOnFlagUntilTimeout>
 8005432:	b120      	cbz	r0, 800543e <HAL_UART_Receive+0x70>
 8005434:	2020      	movs	r0, #32
 8005436:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 800543a:	2003      	movs	r0, #3
 800543c:	e7d6      	b.n	80053ec <HAL_UART_Receive+0x1e>
 800543e:	b945      	cbnz	r5, 8005452 <HAL_UART_Receive+0x84>
 8005440:	6820      	ldr	r0, [r4, #0]
 8005442:	6840      	ldr	r0, [r0, #4]
 8005444:	f3c0 0008 	ubfx	r0, r0, #0, #9
 8005448:	f8a8 0000 	strh.w	r0, [r8]
 800544c:	f108 0802 	add.w	r8, r8, #2
 8005450:	e011      	b.n	8005476 <HAL_UART_Receive+0xa8>
 8005452:	68a0      	ldr	r0, [r4, #8]
 8005454:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 8005458:	d003      	beq.n	8005462 <HAL_UART_Receive+0x94>
 800545a:	68a0      	ldr	r0, [r4, #8]
 800545c:	b928      	cbnz	r0, 800546a <HAL_UART_Receive+0x9c>
 800545e:	6920      	ldr	r0, [r4, #16]
 8005460:	b918      	cbnz	r0, 800546a <HAL_UART_Receive+0x9c>
 8005462:	6820      	ldr	r0, [r4, #0]
 8005464:	6840      	ldr	r0, [r0, #4]
 8005466:	7028      	strb	r0, [r5, #0]
 8005468:	e004      	b.n	8005474 <HAL_UART_Receive+0xa6>
 800546a:	6820      	ldr	r0, [r4, #0]
 800546c:	6840      	ldr	r0, [r0, #4]
 800546e:	f000 007f 	and.w	r0, r0, #127	@ 0x7f
 8005472:	7028      	strb	r0, [r5, #0]
 8005474:	1c6d      	adds	r5, r5, #1
 8005476:	8de0      	ldrh	r0, [r4, #46]	@ 0x2e
 8005478:	1e40      	subs	r0, r0, #1
 800547a:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 800547c:	8de0      	ldrh	r0, [r4, #46]	@ 0x2e
 800547e:	2800      	cmp	r0, #0
 8005480:	d1cf      	bne.n	8005422 <HAL_UART_Receive+0x54>
 8005482:	2020      	movs	r0, #32
 8005484:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8005488:	2000      	movs	r0, #0
 800548a:	e7af      	b.n	80053ec <HAL_UART_Receive+0x1e>
 800548c:	2002      	movs	r0, #2
 800548e:	e7ad      	b.n	80053ec <HAL_UART_Receive+0x1e>

08005490 <HAL_UART_Receive_DMA>:
 8005490:	b570      	push	{r4, r5, r6, lr}
 8005492:	4604      	mov	r4, r0
 8005494:	460d      	mov	r5, r1
 8005496:	4616      	mov	r6, r2
 8005498:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 800549c:	2820      	cmp	r0, #32
 800549e:	d10b      	bne.n	80054b8 <HAL_UART_Receive_DMA+0x28>
 80054a0:	b105      	cbz	r5, 80054a4 <HAL_UART_Receive_DMA+0x14>
 80054a2:	b90e      	cbnz	r6, 80054a8 <HAL_UART_Receive_DMA+0x18>
 80054a4:	2001      	movs	r0, #1
 80054a6:	bd70      	pop	{r4, r5, r6, pc}
 80054a8:	2000      	movs	r0, #0
 80054aa:	6320      	str	r0, [r4, #48]	@ 0x30
 80054ac:	4632      	mov	r2, r6
 80054ae:	4629      	mov	r1, r5
 80054b0:	4620      	mov	r0, r4
 80054b2:	f000 fc49 	bl	8005d48 <UART_Start_Receive_DMA>
 80054b6:	e7f6      	b.n	80054a6 <HAL_UART_Receive_DMA+0x16>
 80054b8:	2002      	movs	r0, #2
 80054ba:	e7f4      	b.n	80054a6 <HAL_UART_Receive_DMA+0x16>

080054bc <HAL_UART_Receive_IT>:
 80054bc:	b570      	push	{r4, r5, r6, lr}
 80054be:	4604      	mov	r4, r0
 80054c0:	460d      	mov	r5, r1
 80054c2:	4616      	mov	r6, r2
 80054c4:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 80054c8:	2820      	cmp	r0, #32
 80054ca:	d10b      	bne.n	80054e4 <HAL_UART_Receive_IT+0x28>
 80054cc:	b105      	cbz	r5, 80054d0 <HAL_UART_Receive_IT+0x14>
 80054ce:	b90e      	cbnz	r6, 80054d4 <HAL_UART_Receive_IT+0x18>
 80054d0:	2001      	movs	r0, #1
 80054d2:	bd70      	pop	{r4, r5, r6, pc}
 80054d4:	2000      	movs	r0, #0
 80054d6:	6320      	str	r0, [r4, #48]	@ 0x30
 80054d8:	4632      	mov	r2, r6
 80054da:	4629      	mov	r1, r5
 80054dc:	4620      	mov	r0, r4
 80054de:	f000 fc97 	bl	8005e10 <UART_Start_Receive_IT>
 80054e2:	e7f6      	b.n	80054d2 <HAL_UART_Receive_IT+0x16>
 80054e4:	2002      	movs	r0, #2
 80054e6:	e7f4      	b.n	80054d2 <HAL_UART_Receive_IT+0x16>

080054e8 <HAL_UART_RxCpltCallback>:
 80054e8:	4770      	bx	lr

080054ea <HAL_UART_RxHalfCpltCallback>:
 80054ea:	4770      	bx	lr

080054ec <HAL_UART_Transmit>:
 80054ec:	e92d 4ff8 	stmdb	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
 80054f0:	4604      	mov	r4, r0
 80054f2:	460e      	mov	r6, r1
 80054f4:	4617      	mov	r7, r2
 80054f6:	4699      	mov	r9, r3
 80054f8:	f04f 0a00 	mov.w	sl, #0
 80054fc:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 8005500:	2820      	cmp	r0, #32
 8005502:	d150      	bne.n	80055a6 <HAL_UART_Transmit+0xba>
 8005504:	b106      	cbz	r6, 8005508 <HAL_UART_Transmit+0x1c>
 8005506:	b917      	cbnz	r7, 800550e <HAL_UART_Transmit+0x22>
 8005508:	2001      	movs	r0, #1
 800550a:	e8bd 8ff8 	ldmia.w	sp!, {r3, r4, r5, r6, r7, r8, r9, sl, fp, pc}
 800550e:	2000      	movs	r0, #0
 8005510:	6460      	str	r0, [r4, #68]	@ 0x44
 8005512:	2021      	movs	r0, #33	@ 0x21
 8005514:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005518:	f7fd fdae 	bl	8003078 <HAL_GetTick>
 800551c:	4682      	mov	sl, r0
 800551e:	84a7      	strh	r7, [r4, #36]	@ 0x24
 8005520:	84e7      	strh	r7, [r4, #38]	@ 0x26
 8005522:	68a0      	ldr	r0, [r4, #8]
 8005524:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 8005528:	d104      	bne.n	8005534 <HAL_UART_Transmit+0x48>
 800552a:	6920      	ldr	r0, [r4, #16]
 800552c:	b910      	cbnz	r0, 8005534 <HAL_UART_Transmit+0x48>
 800552e:	2500      	movs	r5, #0
 8005530:	46b0      	mov	r8, r6
 8005532:	e002      	b.n	800553a <HAL_UART_Transmit+0x4e>
 8005534:	4635      	mov	r5, r6
 8005536:	f04f 0800 	mov.w	r8, #0
 800553a:	e01e      	b.n	800557a <HAL_UART_Transmit+0x8e>
 800553c:	4653      	mov	r3, sl
 800553e:	2200      	movs	r2, #0
 8005540:	2180      	movs	r1, #128	@ 0x80
 8005542:	4620      	mov	r0, r4
 8005544:	f8cd 9000 	str.w	r9, [sp]
 8005548:	f000 fcb2 	bl	8005eb0 <UART_WaitOnFlagUntilTimeout>
 800554c:	b120      	cbz	r0, 8005558 <HAL_UART_Transmit+0x6c>
 800554e:	2020      	movs	r0, #32
 8005550:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005554:	2003      	movs	r0, #3
 8005556:	e7d8      	b.n	800550a <HAL_UART_Transmit+0x1e>
 8005558:	b945      	cbnz	r5, 800556c <HAL_UART_Transmit+0x80>
 800555a:	f8b8 0000 	ldrh.w	r0, [r8]
 800555e:	f3c0 0008 	ubfx	r0, r0, #0, #9
 8005562:	6821      	ldr	r1, [r4, #0]
 8005564:	6048      	str	r0, [r1, #4]
 8005566:	f108 0802 	add.w	r8, r8, #2
 800556a:	e003      	b.n	8005574 <HAL_UART_Transmit+0x88>
 800556c:	7828      	ldrb	r0, [r5, #0]
 800556e:	6821      	ldr	r1, [r4, #0]
 8005570:	6048      	str	r0, [r1, #4]
 8005572:	1c6d      	adds	r5, r5, #1
 8005574:	8ce0      	ldrh	r0, [r4, #38]	@ 0x26
 8005576:	1e40      	subs	r0, r0, #1
 8005578:	84e0      	strh	r0, [r4, #38]	@ 0x26
 800557a:	8ce0      	ldrh	r0, [r4, #38]	@ 0x26
 800557c:	2800      	cmp	r0, #0
 800557e:	d1dd      	bne.n	800553c <HAL_UART_Transmit+0x50>
 8005580:	4653      	mov	r3, sl
 8005582:	2200      	movs	r2, #0
 8005584:	2140      	movs	r1, #64	@ 0x40
 8005586:	4620      	mov	r0, r4
 8005588:	f8cd 9000 	str.w	r9, [sp]
 800558c:	f000 fc90 	bl	8005eb0 <UART_WaitOnFlagUntilTimeout>
 8005590:	b120      	cbz	r0, 800559c <HAL_UART_Transmit+0xb0>
 8005592:	2020      	movs	r0, #32
 8005594:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005598:	2003      	movs	r0, #3
 800559a:	e7b6      	b.n	800550a <HAL_UART_Transmit+0x1e>
 800559c:	2020      	movs	r0, #32
 800559e:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 80055a2:	2000      	movs	r0, #0
 80055a4:	e7b1      	b.n	800550a <HAL_UART_Transmit+0x1e>
 80055a6:	2002      	movs	r0, #2
 80055a8:	e7af      	b.n	800550a <HAL_UART_Transmit+0x1e>
	...

080055ac <HAL_UART_Transmit_DMA>:
 80055ac:	b5f7      	push	{r0, r1, r2, r4, r5, r6, r7, lr}
 80055ae:	4604      	mov	r4, r0
 80055b0:	4615      	mov	r5, r2
 80055b2:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 80055b6:	2820      	cmp	r0, #32
 80055b8:	d136      	bne.n	8005628 <HAL_UART_Transmit_DMA+0x7c>
 80055ba:	9801      	ldr	r0, [sp, #4]
 80055bc:	b100      	cbz	r0, 80055c0 <HAL_UART_Transmit_DMA+0x14>
 80055be:	b90d      	cbnz	r5, 80055c4 <HAL_UART_Transmit_DMA+0x18>
 80055c0:	2001      	movs	r0, #1
 80055c2:	bdfe      	pop	{r1, r2, r3, r4, r5, r6, r7, pc}
 80055c4:	9801      	ldr	r0, [sp, #4]
 80055c6:	6220      	str	r0, [r4, #32]
 80055c8:	84a5      	strh	r5, [r4, #36]	@ 0x24
 80055ca:	84e5      	strh	r5, [r4, #38]	@ 0x26
 80055cc:	2000      	movs	r0, #0
 80055ce:	6460      	str	r0, [r4, #68]	@ 0x44
 80055d0:	2021      	movs	r0, #33	@ 0x21
 80055d2:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 80055d6:	4815      	ldr	r0, [pc, #84]	@ (800562c <HAL_UART_Transmit_DMA+0x80>)
 80055d8:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 80055da:	6288      	str	r0, [r1, #40]	@ 0x28
 80055dc:	4814      	ldr	r0, [pc, #80]	@ (8005630 <HAL_UART_Transmit_DMA+0x84>)
 80055de:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 80055e0:	62c8      	str	r0, [r1, #44]	@ 0x2c
 80055e2:	4814      	ldr	r0, [pc, #80]	@ (8005634 <HAL_UART_Transmit_DMA+0x88>)
 80055e4:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 80055e6:	6308      	str	r0, [r1, #48]	@ 0x30
 80055e8:	2000      	movs	r0, #0
 80055ea:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 80055ec:	6348      	str	r0, [r1, #52]	@ 0x34
 80055ee:	ae01      	add	r6, sp, #4
 80055f0:	6823      	ldr	r3, [r4, #0]
 80055f2:	1d1a      	adds	r2, r3, #4
 80055f4:	6831      	ldr	r1, [r6, #0]
 80055f6:	462b      	mov	r3, r5
 80055f8:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 80055fa:	f7fc fdb5 	bl	8002168 <HAL_DMA_Start_IT>
 80055fe:	f06f 0040 	mvn.w	r0, #64	@ 0x40
 8005602:	6821      	ldr	r1, [r4, #0]
 8005604:	6008      	str	r0, [r1, #0]
 8005606:	bf00      	nop
 8005608:	bf00      	nop
 800560a:	6821      	ldr	r1, [r4, #0]
 800560c:	3114      	adds	r1, #20
 800560e:	e851 1f00 	ldrex	r1, [r1]
 8005612:	f041 0080 	orr.w	r0, r1, #128	@ 0x80
 8005616:	6821      	ldr	r1, [r4, #0]
 8005618:	3114      	adds	r1, #20
 800561a:	e841 0200 	strex	r2, r0, [r1]
 800561e:	2a00      	cmp	r2, #0
 8005620:	d1f3      	bne.n	800560a <HAL_UART_Transmit_DMA+0x5e>
 8005622:	bf00      	nop
 8005624:	2000      	movs	r0, #0
 8005626:	e7cc      	b.n	80055c2 <HAL_UART_Transmit_DMA+0x16>
 8005628:	2002      	movs	r0, #2
 800562a:	e7ca      	b.n	80055c2 <HAL_UART_Transmit_DMA+0x16>
 800562c:	080059e7 	.word	0x080059e7
 8005630:	08005a77 	.word	0x08005a77
 8005634:	0800586b 	.word	0x0800586b

08005638 <HAL_UART_Transmit_IT>:
 8005638:	b510      	push	{r4, lr}
 800563a:	4603      	mov	r3, r0
 800563c:	f893 0041 	ldrb.w	r0, [r3, #65]	@ 0x41
 8005640:	2820      	cmp	r0, #32
 8005642:	d113      	bne.n	800566c <HAL_UART_Transmit_IT+0x34>
 8005644:	b101      	cbz	r1, 8005648 <HAL_UART_Transmit_IT+0x10>
 8005646:	b90a      	cbnz	r2, 800564c <HAL_UART_Transmit_IT+0x14>
 8005648:	2001      	movs	r0, #1
 800564a:	bd10      	pop	{r4, pc}
 800564c:	6219      	str	r1, [r3, #32]
 800564e:	849a      	strh	r2, [r3, #36]	@ 0x24
 8005650:	84da      	strh	r2, [r3, #38]	@ 0x26
 8005652:	2000      	movs	r0, #0
 8005654:	6458      	str	r0, [r3, #68]	@ 0x44
 8005656:	2021      	movs	r0, #33	@ 0x21
 8005658:	f883 0041 	strb.w	r0, [r3, #65]	@ 0x41
 800565c:	6818      	ldr	r0, [r3, #0]
 800565e:	68c0      	ldr	r0, [r0, #12]
 8005660:	f040 0080 	orr.w	r0, r0, #128	@ 0x80
 8005664:	681c      	ldr	r4, [r3, #0]
 8005666:	60e0      	str	r0, [r4, #12]
 8005668:	2000      	movs	r0, #0
 800566a:	e7ee      	b.n	800564a <HAL_UART_Transmit_IT+0x12>
 800566c:	2002      	movs	r0, #2
 800566e:	e7ec      	b.n	800564a <HAL_UART_Transmit_IT+0x12>

08005670 <HAL_UART_TxCpltCallback>:
 8005670:	4770      	bx	lr

08005672 <HAL_UART_TxHalfCpltCallback>:
 8005672:	4770      	bx	lr

08005674 <HardFault_Handler>:
 8005674:	bf00      	nop
 8005676:	e7fe      	b.n	8005676 <HardFault_Handler+0x2>

08005678 <MX_GPIO_Init>:
 8005678:	b508      	push	{r3, lr}
 800567a:	bf00      	nop
 800567c:	4813      	ldr	r0, [pc, #76]	@ (80056cc <MX_GPIO_Init+0x54>)
 800567e:	6980      	ldr	r0, [r0, #24]
 8005680:	f040 0010 	orr.w	r0, r0, #16
 8005684:	4911      	ldr	r1, [pc, #68]	@ (80056cc <MX_GPIO_Init+0x54>)
 8005686:	6188      	str	r0, [r1, #24]
 8005688:	4608      	mov	r0, r1
 800568a:	6980      	ldr	r0, [r0, #24]
 800568c:	f000 0010 	and.w	r0, r0, #16
 8005690:	9000      	str	r0, [sp, #0]
 8005692:	bf00      	nop
 8005694:	bf00      	nop
 8005696:	bf00      	nop
 8005698:	4608      	mov	r0, r1
 800569a:	6980      	ldr	r0, [r0, #24]
 800569c:	f040 0020 	orr.w	r0, r0, #32
 80056a0:	6188      	str	r0, [r1, #24]
 80056a2:	4608      	mov	r0, r1
 80056a4:	6980      	ldr	r0, [r0, #24]
 80056a6:	f000 0020 	and.w	r0, r0, #32
 80056aa:	9000      	str	r0, [sp, #0]
 80056ac:	bf00      	nop
 80056ae:	bf00      	nop
 80056b0:	bf00      	nop
 80056b2:	4608      	mov	r0, r1
 80056b4:	6980      	ldr	r0, [r0, #24]
 80056b6:	f040 0004 	orr.w	r0, r0, #4
 80056ba:	6188      	str	r0, [r1, #24]
 80056bc:	4608      	mov	r0, r1
 80056be:	6980      	ldr	r0, [r0, #24]
 80056c0:	f000 0004 	and.w	r0, r0, #4
 80056c4:	9000      	str	r0, [sp, #0]
 80056c6:	bf00      	nop
 80056c8:	bf00      	nop
 80056ca:	bd08      	pop	{r3, pc}
 80056cc:	40021000 	.word	0x40021000

080056d0 <MX_USART1_UART_Init>:
 80056d0:	b510      	push	{r4, lr}
 80056d2:	480b      	ldr	r0, [pc, #44]	@ (8005700 <MX_USART1_UART_Init+0x30>)
 80056d4:	490b      	ldr	r1, [pc, #44]	@ (8005704 <MX_USART1_UART_Init+0x34>)
 80056d6:	6008      	str	r0, [r1, #0]
 80056d8:	f44f 30e1 	mov.w	r0, #115200	@ 0x1c200
 80056dc:	6048      	str	r0, [r1, #4]
 80056de:	2100      	movs	r1, #0
 80056e0:	4808      	ldr	r0, [pc, #32]	@ (8005704 <MX_USART1_UART_Init+0x34>)
 80056e2:	6081      	str	r1, [r0, #8]
 80056e4:	60c1      	str	r1, [r0, #12]
 80056e6:	6101      	str	r1, [r0, #16]
 80056e8:	210c      	movs	r1, #12
 80056ea:	6141      	str	r1, [r0, #20]
 80056ec:	2100      	movs	r1, #0
 80056ee:	6181      	str	r1, [r0, #24]
 80056f0:	61c1      	str	r1, [r0, #28]
 80056f2:	f7ff fdd1 	bl	8005298 <HAL_UART_Init>
 80056f6:	b108      	cbz	r0, 80056fc <MX_USART1_UART_Init+0x2c>
 80056f8:	f7fb fbc1 	bl	8000e7e <Error_Handler>
 80056fc:	bd10      	pop	{r4, pc}
 80056fe:	0000      	.short	0x0000
 8005700:	40013800 	.word	0x40013800
 8005704:	20000028 	.word	0x20000028

08005708 <MemManage_Handler>:
 8005708:	bf00      	nop
 800570a:	e7fe      	b.n	800570a <MemManage_Handler+0x2>

0800570c <NMI_Handler>:
 800570c:	bf00      	nop
 800570e:	e7fe      	b.n	800570e <NMI_Handler+0x2>

08005710 <PWR_OverloadWfe>:
 8005710:	bf20      	wfe
 8005712:	bf00      	nop
 8005714:	4770      	bx	lr

08005716 <PendSV_Handler>:
 8005716:	4770      	bx	lr

08005718 <RCC_Delay>:
 8005718:	b508      	push	{r3, lr}
 800571a:	4908      	ldr	r1, [pc, #32]	@ (800573c <RCC_Delay+0x24>)
 800571c:	6809      	ldr	r1, [r1, #0]
 800571e:	08c9      	lsrs	r1, r1, #3
 8005720:	f44f 727a 	mov.w	r2, #1000	@ 0x3e8
 8005724:	fbb1 f1f2 	udiv	r1, r1, r2
 8005728:	4341      	muls	r1, r0
 800572a:	9100      	str	r1, [sp, #0]
 800572c:	bf00      	nop
 800572e:	bf00      	nop
 8005730:	9900      	ldr	r1, [sp, #0]
 8005732:	1e4a      	subs	r2, r1, #1
 8005734:	9200      	str	r2, [sp, #0]
 8005736:	2900      	cmp	r1, #0
 8005738:	d1f9      	bne.n	800572e <RCC_Delay+0x16>
 800573a:	bd08      	pop	{r3, pc}
 800573c:	20000018 	.word	0x20000018

08005740 <SVC_Handler>:
 8005740:	4770      	bx	lr

08005742 <SysTick_Handler>:
 8005742:	b510      	push	{r4, lr}
 8005744:	f7fd fd3e 	bl	80031c4 <HAL_IncTick>
 8005748:	bd10      	pop	{r4, pc}

0800574a <SystemClock_Config>:
 800574a:	b500      	push	{lr}
 800574c:	b08f      	sub	sp, #60	@ 0x3c
 800574e:	2128      	movs	r1, #40	@ 0x28
 8005750:	a805      	add	r0, sp, #20
 8005752:	f7fa fe08 	bl	8000366 <__aeabi_memclr>
 8005756:	2114      	movs	r1, #20
 8005758:	4668      	mov	r0, sp
 800575a:	f7fa fe04 	bl	8000366 <__aeabi_memclr>
 800575e:	2001      	movs	r0, #1
 8005760:	9005      	str	r0, [sp, #20]
 8005762:	0400      	lsls	r0, r0, #16
 8005764:	9006      	str	r0, [sp, #24]
 8005766:	2000      	movs	r0, #0
 8005768:	9007      	str	r0, [sp, #28]
 800576a:	2001      	movs	r0, #1
 800576c:	9009      	str	r0, [sp, #36]	@ 0x24
 800576e:	2002      	movs	r0, #2
 8005770:	900c      	str	r0, [sp, #48]	@ 0x30
 8005772:	03c1      	lsls	r1, r0, #15
 8005774:	910d      	str	r1, [sp, #52]	@ 0x34
 8005776:	f44f 11e0 	mov.w	r1, #1835008	@ 0x1c0000
 800577a:	910e      	str	r1, [sp, #56]	@ 0x38
 800577c:	a805      	add	r0, sp, #20
 800577e:	f7fe fce1 	bl	8004144 <HAL_RCC_OscConfig>
 8005782:	b108      	cbz	r0, 8005788 <SystemClock_Config+0x3e>
 8005784:	f7fb fb7b 	bl	8000e7e <Error_Handler>
 8005788:	200f      	movs	r0, #15
 800578a:	9000      	str	r0, [sp, #0]
 800578c:	2002      	movs	r0, #2
 800578e:	9001      	str	r0, [sp, #4]
 8005790:	2000      	movs	r0, #0
 8005792:	9002      	str	r0, [sp, #8]
 8005794:	f44f 6080 	mov.w	r0, #1024	@ 0x400
 8005798:	9003      	str	r0, [sp, #12]
 800579a:	2000      	movs	r0, #0
 800579c:	9004      	str	r0, [sp, #16]
 800579e:	2102      	movs	r1, #2
 80057a0:	4668      	mov	r0, sp
 80057a2:	f7fe fa4f 	bl	8003c44 <HAL_RCC_ClockConfig>
 80057a6:	b108      	cbz	r0, 80057ac <SystemClock_Config+0x62>
 80057a8:	f7fb fb69 	bl	8000e7e <Error_Handler>
 80057ac:	b00f      	add	sp, #60	@ 0x3c
 80057ae:	bd00      	pop	{pc}

080057b0 <SystemCoreClockUpdate>:
 80057b0:	b510      	push	{r4, lr}
 80057b2:	2100      	movs	r1, #0
 80057b4:	2000      	movs	r0, #0
 80057b6:	2200      	movs	r2, #0
 80057b8:	4b21      	ldr	r3, [pc, #132]	@ (8005840 <SystemCoreClockUpdate+0x90>)
 80057ba:	685b      	ldr	r3, [r3, #4]
 80057bc:	f003 010c 	and.w	r1, r3, #12
 80057c0:	b121      	cbz	r1, 80057cc <SystemCoreClockUpdate+0x1c>
 80057c2:	2904      	cmp	r1, #4
 80057c4:	d006      	beq.n	80057d4 <SystemCoreClockUpdate+0x24>
 80057c6:	2908      	cmp	r1, #8
 80057c8:	d128      	bne.n	800581c <SystemCoreClockUpdate+0x6c>
 80057ca:	e007      	b.n	80057dc <SystemCoreClockUpdate+0x2c>
 80057cc:	4b1d      	ldr	r3, [pc, #116]	@ (8005844 <SystemCoreClockUpdate+0x94>)
 80057ce:	4c1e      	ldr	r4, [pc, #120]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 80057d0:	6023      	str	r3, [r4, #0]
 80057d2:	e027      	b.n	8005824 <SystemCoreClockUpdate+0x74>
 80057d4:	4b1b      	ldr	r3, [pc, #108]	@ (8005844 <SystemCoreClockUpdate+0x94>)
 80057d6:	4c1c      	ldr	r4, [pc, #112]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 80057d8:	6023      	str	r3, [r4, #0]
 80057da:	e023      	b.n	8005824 <SystemCoreClockUpdate+0x74>
 80057dc:	4b18      	ldr	r3, [pc, #96]	@ (8005840 <SystemCoreClockUpdate+0x90>)
 80057de:	685b      	ldr	r3, [r3, #4]
 80057e0:	f403 1070 	and.w	r0, r3, #3932160	@ 0x3c0000
 80057e4:	4b16      	ldr	r3, [pc, #88]	@ (8005840 <SystemCoreClockUpdate+0x90>)
 80057e6:	685b      	ldr	r3, [r3, #4]
 80057e8:	f403 3280 	and.w	r2, r3, #65536	@ 0x10000
 80057ec:	2302      	movs	r3, #2
 80057ee:	eb03 4090 	add.w	r0, r3, r0, lsr #18
 80057f2:	b922      	cbnz	r2, 80057fe <SystemCoreClockUpdate+0x4e>
 80057f4:	4b15      	ldr	r3, [pc, #84]	@ (800584c <SystemCoreClockUpdate+0x9c>)
 80057f6:	4343      	muls	r3, r0
 80057f8:	4c13      	ldr	r4, [pc, #76]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 80057fa:	6023      	str	r3, [r4, #0]
 80057fc:	e00d      	b.n	800581a <SystemCoreClockUpdate+0x6a>
 80057fe:	4b10      	ldr	r3, [pc, #64]	@ (8005840 <SystemCoreClockUpdate+0x90>)
 8005800:	685b      	ldr	r3, [r3, #4]
 8005802:	f403 3300 	and.w	r3, r3, #131072	@ 0x20000
 8005806:	b123      	cbz	r3, 8005812 <SystemCoreClockUpdate+0x62>
 8005808:	4b10      	ldr	r3, [pc, #64]	@ (800584c <SystemCoreClockUpdate+0x9c>)
 800580a:	4343      	muls	r3, r0
 800580c:	4c0e      	ldr	r4, [pc, #56]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 800580e:	6023      	str	r3, [r4, #0]
 8005810:	e003      	b.n	800581a <SystemCoreClockUpdate+0x6a>
 8005812:	4b0c      	ldr	r3, [pc, #48]	@ (8005844 <SystemCoreClockUpdate+0x94>)
 8005814:	4343      	muls	r3, r0
 8005816:	4c0c      	ldr	r4, [pc, #48]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 8005818:	6023      	str	r3, [r4, #0]
 800581a:	e003      	b.n	8005824 <SystemCoreClockUpdate+0x74>
 800581c:	4b09      	ldr	r3, [pc, #36]	@ (8005844 <SystemCoreClockUpdate+0x94>)
 800581e:	4c0a      	ldr	r4, [pc, #40]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 8005820:	6023      	str	r3, [r4, #0]
 8005822:	bf00      	nop
 8005824:	bf00      	nop
 8005826:	4b06      	ldr	r3, [pc, #24]	@ (8005840 <SystemCoreClockUpdate+0x90>)
 8005828:	685b      	ldr	r3, [r3, #4]
 800582a:	f3c3 1303 	ubfx	r3, r3, #4, #4
 800582e:	4c08      	ldr	r4, [pc, #32]	@ (8005850 <SystemCoreClockUpdate+0xa0>)
 8005830:	5ce1      	ldrb	r1, [r4, r3]
 8005832:	4b05      	ldr	r3, [pc, #20]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 8005834:	681b      	ldr	r3, [r3, #0]
 8005836:	40cb      	lsrs	r3, r1
 8005838:	4c03      	ldr	r4, [pc, #12]	@ (8005848 <SystemCoreClockUpdate+0x98>)
 800583a:	6023      	str	r3, [r4, #0]
 800583c:	bd10      	pop	{r4, pc}
 800583e:	0000      	.short	0x0000
 8005840:	40021000 	.word	0x40021000
 8005844:	007a1200 	.word	0x007a1200
 8005848:	20000018 	.word	0x20000018
 800584c:	003d0900 	.word	0x003d0900
 8005850:	08006ca9 	.word	0x08006ca9

08005854 <SystemInit>:
 8005854:	4770      	bx	lr

08005856 <UART_DMAAbortOnError>:
 8005856:	b570      	push	{r4, r5, r6, lr}
 8005858:	4605      	mov	r5, r0
 800585a:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 800585c:	2000      	movs	r0, #0
 800585e:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8005860:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8005862:	4620      	mov	r0, r4
 8005864:	f7ff fb98 	bl	8004f98 <HAL_UART_ErrorCallback>
 8005868:	bd70      	pop	{r4, r5, r6, pc}

0800586a <UART_DMAError>:
 800586a:	b570      	push	{r4, r5, r6, lr}
 800586c:	4606      	mov	r6, r0
 800586e:	2500      	movs	r5, #0
 8005870:	6a74      	ldr	r4, [r6, #36]	@ 0x24
 8005872:	6820      	ldr	r0, [r4, #0]
 8005874:	6940      	ldr	r0, [r0, #20]
 8005876:	f3c0 15c0 	ubfx	r5, r0, #7, #1
 800587a:	f894 0041 	ldrb.w	r0, [r4, #65]	@ 0x41
 800587e:	2821      	cmp	r0, #33	@ 0x21
 8005880:	d105      	bne.n	800588e <UART_DMAError+0x24>
 8005882:	b125      	cbz	r5, 800588e <UART_DMAError+0x24>
 8005884:	2000      	movs	r0, #0
 8005886:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8005888:	4620      	mov	r0, r4
 800588a:	f000 f94d 	bl	8005b28 <UART_EndTxTransfer>
 800588e:	6820      	ldr	r0, [r4, #0]
 8005890:	6940      	ldr	r0, [r0, #20]
 8005892:	f3c0 1580 	ubfx	r5, r0, #6, #1
 8005896:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 800589a:	2822      	cmp	r0, #34	@ 0x22
 800589c:	d105      	bne.n	80058aa <UART_DMAError+0x40>
 800589e:	b125      	cbz	r5, 80058aa <UART_DMAError+0x40>
 80058a0:	2000      	movs	r0, #0
 80058a2:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 80058a4:	4620      	mov	r0, r4
 80058a6:	f000 f8f9 	bl	8005a9c <UART_EndRxTransfer>
 80058aa:	6c60      	ldr	r0, [r4, #68]	@ 0x44
 80058ac:	f040 0010 	orr.w	r0, r0, #16
 80058b0:	6460      	str	r0, [r4, #68]	@ 0x44
 80058b2:	4620      	mov	r0, r4
 80058b4:	f7ff fb70 	bl	8004f98 <HAL_UART_ErrorCallback>
 80058b8:	bd70      	pop	{r4, r5, r6, pc}

080058ba <UART_DMAReceiveCplt>:
 80058ba:	b570      	push	{r4, r5, r6, lr}
 80058bc:	4605      	mov	r5, r0
 80058be:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 80058c0:	6828      	ldr	r0, [r5, #0]
 80058c2:	6800      	ldr	r0, [r0, #0]
 80058c4:	f000 0020 	and.w	r0, r0, #32
 80058c8:	2800      	cmp	r0, #0
 80058ca:	d142      	bne.n	8005952 <UART_DMAReceiveCplt+0x98>
 80058cc:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 80058ce:	bf00      	nop
 80058d0:	bf00      	nop
 80058d2:	6821      	ldr	r1, [r4, #0]
 80058d4:	310c      	adds	r1, #12
 80058d6:	e851 1f00 	ldrex	r1, [r1]
 80058da:	f421 7080 	bic.w	r0, r1, #256	@ 0x100
 80058de:	6821      	ldr	r1, [r4, #0]
 80058e0:	310c      	adds	r1, #12
 80058e2:	e841 0200 	strex	r2, r0, [r1]
 80058e6:	2a00      	cmp	r2, #0
 80058e8:	d1f3      	bne.n	80058d2 <UART_DMAReceiveCplt+0x18>
 80058ea:	bf00      	nop
 80058ec:	bf00      	nop
 80058ee:	bf00      	nop
 80058f0:	6821      	ldr	r1, [r4, #0]
 80058f2:	3114      	adds	r1, #20
 80058f4:	e851 1f00 	ldrex	r1, [r1]
 80058f8:	f021 0001 	bic.w	r0, r1, #1
 80058fc:	6821      	ldr	r1, [r4, #0]
 80058fe:	3114      	adds	r1, #20
 8005900:	e841 0200 	strex	r2, r0, [r1]
 8005904:	2a00      	cmp	r2, #0
 8005906:	d1f3      	bne.n	80058f0 <UART_DMAReceiveCplt+0x36>
 8005908:	bf00      	nop
 800590a:	bf00      	nop
 800590c:	bf00      	nop
 800590e:	6821      	ldr	r1, [r4, #0]
 8005910:	3114      	adds	r1, #20
 8005912:	e851 1f00 	ldrex	r1, [r1]
 8005916:	f021 0040 	bic.w	r0, r1, #64	@ 0x40
 800591a:	6821      	ldr	r1, [r4, #0]
 800591c:	3114      	adds	r1, #20
 800591e:	e841 0200 	strex	r2, r0, [r1]
 8005922:	2a00      	cmp	r2, #0
 8005924:	d1f3      	bne.n	800590e <UART_DMAReceiveCplt+0x54>
 8005926:	bf00      	nop
 8005928:	2020      	movs	r0, #32
 800592a:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 800592e:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 8005930:	2801      	cmp	r0, #1
 8005932:	d10e      	bne.n	8005952 <UART_DMAReceiveCplt+0x98>
 8005934:	bf00      	nop
 8005936:	bf00      	nop
 8005938:	6821      	ldr	r1, [r4, #0]
 800593a:	310c      	adds	r1, #12
 800593c:	e851 1f00 	ldrex	r1, [r1]
 8005940:	f021 0010 	bic.w	r0, r1, #16
 8005944:	6821      	ldr	r1, [r4, #0]
 8005946:	310c      	adds	r1, #12
 8005948:	e841 0200 	strex	r2, r0, [r1]
 800594c:	2a00      	cmp	r2, #0
 800594e:	d1f3      	bne.n	8005938 <UART_DMAReceiveCplt+0x7e>
 8005950:	bf00      	nop
 8005952:	2000      	movs	r0, #0
 8005954:	6360      	str	r0, [r4, #52]	@ 0x34
 8005956:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 8005958:	2801      	cmp	r0, #1
 800595a:	d104      	bne.n	8005966 <UART_DMAReceiveCplt+0xac>
 800595c:	8da1      	ldrh	r1, [r4, #44]	@ 0x2c
 800595e:	4620      	mov	r0, r4
 8005960:	f7fe ff87 	bl	8004872 <HAL_UARTEx_RxEventCallback>
 8005964:	e002      	b.n	800596c <UART_DMAReceiveCplt+0xb2>
 8005966:	4620      	mov	r0, r4
 8005968:	f7ff fdbe 	bl	80054e8 <HAL_UART_RxCpltCallback>
 800596c:	bd70      	pop	{r4, r5, r6, pc}

0800596e <UART_DMARxAbortCallback>:
 800596e:	b570      	push	{r4, r5, r6, lr}
 8005970:	4605      	mov	r5, r0
 8005972:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 8005974:	2000      	movs	r0, #0
 8005976:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8005978:	6348      	str	r0, [r1, #52]	@ 0x34
 800597a:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 800597c:	b118      	cbz	r0, 8005986 <UART_DMARxAbortCallback+0x18>
 800597e:	6ba0      	ldr	r0, [r4, #56]	@ 0x38
 8005980:	6b40      	ldr	r0, [r0, #52]	@ 0x34
 8005982:	b100      	cbz	r0, 8005986 <UART_DMARxAbortCallback+0x18>
 8005984:	bd70      	pop	{r4, r5, r6, pc}
 8005986:	2000      	movs	r0, #0
 8005988:	84e0      	strh	r0, [r4, #38]	@ 0x26
 800598a:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 800598c:	6460      	str	r0, [r4, #68]	@ 0x44
 800598e:	2020      	movs	r0, #32
 8005990:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005994:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8005998:	2000      	movs	r0, #0
 800599a:	6320      	str	r0, [r4, #48]	@ 0x30
 800599c:	4620      	mov	r0, r4
 800599e:	f7fe fff4 	bl	800498a <HAL_UART_AbortCpltCallback>
 80059a2:	bf00      	nop
 80059a4:	e7ee      	b.n	8005984 <UART_DMARxAbortCallback+0x16>

080059a6 <UART_DMARxHalfCplt>:
 80059a6:	b570      	push	{r4, r5, r6, lr}
 80059a8:	4605      	mov	r5, r0
 80059aa:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 80059ac:	2001      	movs	r0, #1
 80059ae:	6360      	str	r0, [r4, #52]	@ 0x34
 80059b0:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 80059b2:	2801      	cmp	r0, #1
 80059b4:	d105      	bne.n	80059c2 <UART_DMARxHalfCplt+0x1c>
 80059b6:	8da0      	ldrh	r0, [r4, #44]	@ 0x2c
 80059b8:	0841      	lsrs	r1, r0, #1
 80059ba:	4620      	mov	r0, r4
 80059bc:	f7fe ff59 	bl	8004872 <HAL_UARTEx_RxEventCallback>
 80059c0:	e002      	b.n	80059c8 <UART_DMARxHalfCplt+0x22>
 80059c2:	4620      	mov	r0, r4
 80059c4:	f7ff fd91 	bl	80054ea <HAL_UART_RxHalfCpltCallback>
 80059c8:	bd70      	pop	{r4, r5, r6, pc}

080059ca <UART_DMARxOnlyAbortCallback>:
 80059ca:	b570      	push	{r4, r5, r6, lr}
 80059cc:	4605      	mov	r5, r0
 80059ce:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 80059d0:	2000      	movs	r0, #0
 80059d2:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 80059d4:	2020      	movs	r0, #32
 80059d6:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 80059da:	2000      	movs	r0, #0
 80059dc:	6320      	str	r0, [r4, #48]	@ 0x30
 80059de:	4620      	mov	r0, r4
 80059e0:	f7ff f835 	bl	8004a4e <HAL_UART_AbortReceiveCpltCallback>
 80059e4:	bd70      	pop	{r4, r5, r6, pc}

080059e6 <UART_DMATransmitCplt>:
 80059e6:	b570      	push	{r4, r5, r6, lr}
 80059e8:	4605      	mov	r5, r0
 80059ea:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 80059ec:	6828      	ldr	r0, [r5, #0]
 80059ee:	6800      	ldr	r0, [r0, #0]
 80059f0:	f000 0020 	and.w	r0, r0, #32
 80059f4:	b9f8      	cbnz	r0, 8005a36 <UART_DMATransmitCplt+0x50>
 80059f6:	2000      	movs	r0, #0
 80059f8:	84e0      	strh	r0, [r4, #38]	@ 0x26
 80059fa:	bf00      	nop
 80059fc:	bf00      	nop
 80059fe:	6821      	ldr	r1, [r4, #0]
 8005a00:	3114      	adds	r1, #20
 8005a02:	e851 1f00 	ldrex	r1, [r1]
 8005a06:	f021 0080 	bic.w	r0, r1, #128	@ 0x80
 8005a0a:	6821      	ldr	r1, [r4, #0]
 8005a0c:	3114      	adds	r1, #20
 8005a0e:	e841 0200 	strex	r2, r0, [r1]
 8005a12:	2a00      	cmp	r2, #0
 8005a14:	d1f3      	bne.n	80059fe <UART_DMATransmitCplt+0x18>
 8005a16:	bf00      	nop
 8005a18:	bf00      	nop
 8005a1a:	bf00      	nop
 8005a1c:	6821      	ldr	r1, [r4, #0]
 8005a1e:	310c      	adds	r1, #12
 8005a20:	e851 1f00 	ldrex	r1, [r1]
 8005a24:	f041 0040 	orr.w	r0, r1, #64	@ 0x40
 8005a28:	6821      	ldr	r1, [r4, #0]
 8005a2a:	310c      	adds	r1, #12
 8005a2c:	e841 0200 	strex	r2, r0, [r1]
 8005a30:	2a00      	cmp	r2, #0
 8005a32:	d1f3      	bne.n	8005a1c <UART_DMATransmitCplt+0x36>
 8005a34:	e002      	b.n	8005a3c <UART_DMATransmitCplt+0x56>
 8005a36:	4620      	mov	r0, r4
 8005a38:	f7ff fe1a 	bl	8005670 <HAL_UART_TxCpltCallback>
 8005a3c:	bd70      	pop	{r4, r5, r6, pc}

08005a3e <UART_DMATxAbortCallback>:
 8005a3e:	b570      	push	{r4, r5, r6, lr}
 8005a40:	4605      	mov	r5, r0
 8005a42:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 8005a44:	2000      	movs	r0, #0
 8005a46:	6ba1      	ldr	r1, [r4, #56]	@ 0x38
 8005a48:	6348      	str	r0, [r1, #52]	@ 0x34
 8005a4a:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8005a4c:	b118      	cbz	r0, 8005a56 <UART_DMATxAbortCallback+0x18>
 8005a4e:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8005a50:	6b40      	ldr	r0, [r0, #52]	@ 0x34
 8005a52:	b100      	cbz	r0, 8005a56 <UART_DMATxAbortCallback+0x18>
 8005a54:	bd70      	pop	{r4, r5, r6, pc}
 8005a56:	2000      	movs	r0, #0
 8005a58:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8005a5a:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8005a5c:	6460      	str	r0, [r4, #68]	@ 0x44
 8005a5e:	2020      	movs	r0, #32
 8005a60:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005a64:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8005a68:	2000      	movs	r0, #0
 8005a6a:	6320      	str	r0, [r4, #48]	@ 0x30
 8005a6c:	4620      	mov	r0, r4
 8005a6e:	f7fe ff8c 	bl	800498a <HAL_UART_AbortCpltCallback>
 8005a72:	bf00      	nop
 8005a74:	e7ee      	b.n	8005a54 <UART_DMATxAbortCallback+0x16>

08005a76 <UART_DMATxHalfCplt>:
 8005a76:	b570      	push	{r4, r5, r6, lr}
 8005a78:	4604      	mov	r4, r0
 8005a7a:	6a65      	ldr	r5, [r4, #36]	@ 0x24
 8005a7c:	4628      	mov	r0, r5
 8005a7e:	f7ff fdf8 	bl	8005672 <HAL_UART_TxHalfCpltCallback>
 8005a82:	bd70      	pop	{r4, r5, r6, pc}

08005a84 <UART_DMATxOnlyAbortCallback>:
 8005a84:	b570      	push	{r4, r5, r6, lr}
 8005a86:	4605      	mov	r5, r0
 8005a88:	6a6c      	ldr	r4, [r5, #36]	@ 0x24
 8005a8a:	2000      	movs	r0, #0
 8005a8c:	84e0      	strh	r0, [r4, #38]	@ 0x26
 8005a8e:	2020      	movs	r0, #32
 8005a90:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005a94:	4620      	mov	r0, r4
 8005a96:	f7ff f885 	bl	8004ba4 <HAL_UART_AbortTransmitCpltCallback>
 8005a9a:	bd70      	pop	{r4, r5, r6, pc}

08005a9c <UART_EndRxTransfer>:
 8005a9c:	bf00      	nop
 8005a9e:	bf00      	nop
 8005aa0:	6802      	ldr	r2, [r0, #0]
 8005aa2:	320c      	adds	r2, #12
 8005aa4:	e852 2f00 	ldrex	r2, [r2]
 8005aa8:	f422 7190 	bic.w	r1, r2, #288	@ 0x120
 8005aac:	6802      	ldr	r2, [r0, #0]
 8005aae:	320c      	adds	r2, #12
 8005ab0:	e842 1300 	strex	r3, r1, [r2]
 8005ab4:	2b00      	cmp	r3, #0
 8005ab6:	d1f3      	bne.n	8005aa0 <UART_EndRxTransfer+0x4>
 8005ab8:	bf00      	nop
 8005aba:	bf00      	nop
 8005abc:	bf00      	nop
 8005abe:	6802      	ldr	r2, [r0, #0]
 8005ac0:	3214      	adds	r2, #20
 8005ac2:	e852 2f00 	ldrex	r2, [r2]
 8005ac6:	f022 0101 	bic.w	r1, r2, #1
 8005aca:	6802      	ldr	r2, [r0, #0]
 8005acc:	3214      	adds	r2, #20
 8005ace:	e842 1300 	strex	r3, r1, [r2]
 8005ad2:	2b00      	cmp	r3, #0
 8005ad4:	d1f3      	bne.n	8005abe <UART_EndRxTransfer+0x22>
 8005ad6:	bf00      	nop
 8005ad8:	6b01      	ldr	r1, [r0, #48]	@ 0x30
 8005ada:	2901      	cmp	r1, #1
 8005adc:	d10e      	bne.n	8005afc <UART_EndRxTransfer+0x60>
 8005ade:	bf00      	nop
 8005ae0:	bf00      	nop
 8005ae2:	6802      	ldr	r2, [r0, #0]
 8005ae4:	320c      	adds	r2, #12
 8005ae6:	e852 2f00 	ldrex	r2, [r2]
 8005aea:	f022 0110 	bic.w	r1, r2, #16
 8005aee:	6802      	ldr	r2, [r0, #0]
 8005af0:	320c      	adds	r2, #12
 8005af2:	e842 1300 	strex	r3, r1, [r2]
 8005af6:	2b00      	cmp	r3, #0
 8005af8:	d1f3      	bne.n	8005ae2 <UART_EndRxTransfer+0x46>
 8005afa:	bf00      	nop
 8005afc:	2120      	movs	r1, #32
 8005afe:	f880 1042 	strb.w	r1, [r0, #66]	@ 0x42
 8005b02:	2100      	movs	r1, #0
 8005b04:	6301      	str	r1, [r0, #48]	@ 0x30
 8005b06:	4770      	bx	lr

08005b08 <UART_EndTransmit_IT>:
 8005b08:	b510      	push	{r4, lr}
 8005b0a:	4604      	mov	r4, r0
 8005b0c:	6820      	ldr	r0, [r4, #0]
 8005b0e:	68c0      	ldr	r0, [r0, #12]
 8005b10:	f020 0040 	bic.w	r0, r0, #64	@ 0x40
 8005b14:	6821      	ldr	r1, [r4, #0]
 8005b16:	60c8      	str	r0, [r1, #12]
 8005b18:	2020      	movs	r0, #32
 8005b1a:	f884 0041 	strb.w	r0, [r4, #65]	@ 0x41
 8005b1e:	4620      	mov	r0, r4
 8005b20:	f7ff fda6 	bl	8005670 <HAL_UART_TxCpltCallback>
 8005b24:	2000      	movs	r0, #0
 8005b26:	bd10      	pop	{r4, pc}

08005b28 <UART_EndTxTransfer>:
 8005b28:	bf00      	nop
 8005b2a:	bf00      	nop
 8005b2c:	6802      	ldr	r2, [r0, #0]
 8005b2e:	320c      	adds	r2, #12
 8005b30:	e852 2f00 	ldrex	r2, [r2]
 8005b34:	f022 01c0 	bic.w	r1, r2, #192	@ 0xc0
 8005b38:	6802      	ldr	r2, [r0, #0]
 8005b3a:	320c      	adds	r2, #12
 8005b3c:	e842 1300 	strex	r3, r1, [r2]
 8005b40:	2b00      	cmp	r3, #0
 8005b42:	d1f3      	bne.n	8005b2c <UART_EndTxTransfer+0x4>
 8005b44:	bf00      	nop
 8005b46:	2120      	movs	r1, #32
 8005b48:	f880 1041 	strb.w	r1, [r0, #65]	@ 0x41
 8005b4c:	4770      	bx	lr

08005b4e <UART_Receive_IT>:
 8005b4e:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8005b50:	4604      	mov	r4, r0
 8005b52:	f894 0042 	ldrb.w	r0, [r4, #66]	@ 0x42
 8005b56:	2822      	cmp	r0, #34	@ 0x22
 8005b58:	d175      	bne.n	8005c46 <UART_Receive_IT+0xf8>
 8005b5a:	68a0      	ldr	r0, [r4, #8]
 8005b5c:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 8005b60:	d10c      	bne.n	8005b7c <UART_Receive_IT+0x2e>
 8005b62:	6920      	ldr	r0, [r4, #16]
 8005b64:	b950      	cbnz	r0, 8005b7c <UART_Receive_IT+0x2e>
 8005b66:	2500      	movs	r5, #0
 8005b68:	6aa6      	ldr	r6, [r4, #40]	@ 0x28
 8005b6a:	6820      	ldr	r0, [r4, #0]
 8005b6c:	6840      	ldr	r0, [r0, #4]
 8005b6e:	f3c0 0008 	ubfx	r0, r0, #0, #9
 8005b72:	8030      	strh	r0, [r6, #0]
 8005b74:	6aa0      	ldr	r0, [r4, #40]	@ 0x28
 8005b76:	1c80      	adds	r0, r0, #2
 8005b78:	62a0      	str	r0, [r4, #40]	@ 0x28
 8005b7a:	e015      	b.n	8005ba8 <UART_Receive_IT+0x5a>
 8005b7c:	6aa5      	ldr	r5, [r4, #40]	@ 0x28
 8005b7e:	2600      	movs	r6, #0
 8005b80:	68a0      	ldr	r0, [r4, #8]
 8005b82:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 8005b86:	d003      	beq.n	8005b90 <UART_Receive_IT+0x42>
 8005b88:	68a0      	ldr	r0, [r4, #8]
 8005b8a:	b928      	cbnz	r0, 8005b98 <UART_Receive_IT+0x4a>
 8005b8c:	6920      	ldr	r0, [r4, #16]
 8005b8e:	b918      	cbnz	r0, 8005b98 <UART_Receive_IT+0x4a>
 8005b90:	6820      	ldr	r0, [r4, #0]
 8005b92:	6840      	ldr	r0, [r0, #4]
 8005b94:	7028      	strb	r0, [r5, #0]
 8005b96:	e004      	b.n	8005ba2 <UART_Receive_IT+0x54>
 8005b98:	6820      	ldr	r0, [r4, #0]
 8005b9a:	6840      	ldr	r0, [r0, #4]
 8005b9c:	f000 007f 	and.w	r0, r0, #127	@ 0x7f
 8005ba0:	7028      	strb	r0, [r5, #0]
 8005ba2:	6aa0      	ldr	r0, [r4, #40]	@ 0x28
 8005ba4:	1c40      	adds	r0, r0, #1
 8005ba6:	62a0      	str	r0, [r4, #40]	@ 0x28
 8005ba8:	8de0      	ldrh	r0, [r4, #46]	@ 0x2e
 8005baa:	1e40      	subs	r0, r0, #1
 8005bac:	b280      	uxth	r0, r0
 8005bae:	85e0      	strh	r0, [r4, #46]	@ 0x2e
 8005bb0:	2800      	cmp	r0, #0
 8005bb2:	d146      	bne.n	8005c42 <UART_Receive_IT+0xf4>
 8005bb4:	6820      	ldr	r0, [r4, #0]
 8005bb6:	68c0      	ldr	r0, [r0, #12]
 8005bb8:	f020 0020 	bic.w	r0, r0, #32
 8005bbc:	6821      	ldr	r1, [r4, #0]
 8005bbe:	60c8      	str	r0, [r1, #12]
 8005bc0:	6820      	ldr	r0, [r4, #0]
 8005bc2:	68c0      	ldr	r0, [r0, #12]
 8005bc4:	f420 7080 	bic.w	r0, r0, #256	@ 0x100
 8005bc8:	6821      	ldr	r1, [r4, #0]
 8005bca:	60c8      	str	r0, [r1, #12]
 8005bcc:	6820      	ldr	r0, [r4, #0]
 8005bce:	6940      	ldr	r0, [r0, #20]
 8005bd0:	f020 0001 	bic.w	r0, r0, #1
 8005bd4:	6821      	ldr	r1, [r4, #0]
 8005bd6:	6148      	str	r0, [r1, #20]
 8005bd8:	2020      	movs	r0, #32
 8005bda:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8005bde:	2000      	movs	r0, #0
 8005be0:	6360      	str	r0, [r4, #52]	@ 0x34
 8005be2:	6b20      	ldr	r0, [r4, #48]	@ 0x30
 8005be4:	2801      	cmp	r0, #1
 8005be6:	d126      	bne.n	8005c36 <UART_Receive_IT+0xe8>
 8005be8:	2000      	movs	r0, #0
 8005bea:	6320      	str	r0, [r4, #48]	@ 0x30
 8005bec:	bf00      	nop
 8005bee:	bf00      	nop
 8005bf0:	6821      	ldr	r1, [r4, #0]
 8005bf2:	310c      	adds	r1, #12
 8005bf4:	e851 1f00 	ldrex	r1, [r1]
 8005bf8:	f021 0010 	bic.w	r0, r1, #16
 8005bfc:	6821      	ldr	r1, [r4, #0]
 8005bfe:	310c      	adds	r1, #12
 8005c00:	e841 0200 	strex	r2, r0, [r1]
 8005c04:	2a00      	cmp	r2, #0
 8005c06:	d1f3      	bne.n	8005bf0 <UART_Receive_IT+0xa2>
 8005c08:	bf00      	nop
 8005c0a:	6820      	ldr	r0, [r4, #0]
 8005c0c:	6800      	ldr	r0, [r0, #0]
 8005c0e:	f000 0010 	and.w	r0, r0, #16
 8005c12:	2810      	cmp	r0, #16
 8005c14:	d10a      	bne.n	8005c2c <UART_Receive_IT+0xde>
 8005c16:	bf00      	nop
 8005c18:	2000      	movs	r0, #0
 8005c1a:	9000      	str	r0, [sp, #0]
 8005c1c:	6820      	ldr	r0, [r4, #0]
 8005c1e:	6800      	ldr	r0, [r0, #0]
 8005c20:	9000      	str	r0, [sp, #0]
 8005c22:	6820      	ldr	r0, [r4, #0]
 8005c24:	6840      	ldr	r0, [r0, #4]
 8005c26:	9000      	str	r0, [sp, #0]
 8005c28:	bf00      	nop
 8005c2a:	bf00      	nop
 8005c2c:	8da1      	ldrh	r1, [r4, #44]	@ 0x2c
 8005c2e:	4620      	mov	r0, r4
 8005c30:	f7fe fe1f 	bl	8004872 <HAL_UARTEx_RxEventCallback>
 8005c34:	e002      	b.n	8005c3c <UART_Receive_IT+0xee>
 8005c36:	4620      	mov	r0, r4
 8005c38:	f7ff fc56 	bl	80054e8 <HAL_UART_RxCpltCallback>
 8005c3c:	2000      	movs	r0, #0
 8005c3e:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 8005c40:	e001      	b.n	8005c46 <UART_Receive_IT+0xf8>
 8005c42:	2000      	movs	r0, #0
 8005c44:	e7fb      	b.n	8005c3e <UART_Receive_IT+0xf0>
 8005c46:	2002      	movs	r0, #2
 8005c48:	e7f9      	b.n	8005c3e <UART_Receive_IT+0xf0>
	...

08005c4c <UART_SetConfig>:
 8005c4c:	b570      	push	{r4, r5, r6, lr}
 8005c4e:	4604      	mov	r4, r0
 8005c50:	6821      	ldr	r1, [r4, #0]
 8005c52:	6909      	ldr	r1, [r1, #16]
 8005c54:	f421 5140 	bic.w	r1, r1, #12288	@ 0x3000
 8005c58:	68e2      	ldr	r2, [r4, #12]
 8005c5a:	4311      	orrs	r1, r2
 8005c5c:	6822      	ldr	r2, [r4, #0]
 8005c5e:	6111      	str	r1, [r2, #16]
 8005c60:	6922      	ldr	r2, [r4, #16]
 8005c62:	68a1      	ldr	r1, [r4, #8]
 8005c64:	4311      	orrs	r1, r2
 8005c66:	6962      	ldr	r2, [r4, #20]
 8005c68:	ea41 0502 	orr.w	r5, r1, r2
 8005c6c:	6821      	ldr	r1, [r4, #0]
 8005c6e:	68c9      	ldr	r1, [r1, #12]
 8005c70:	f241 620c 	movw	r2, #5644	@ 0x160c
 8005c74:	4391      	bics	r1, r2
 8005c76:	4329      	orrs	r1, r5
 8005c78:	6822      	ldr	r2, [r4, #0]
 8005c7a:	60d1      	str	r1, [r2, #12]
 8005c7c:	6821      	ldr	r1, [r4, #0]
 8005c7e:	6949      	ldr	r1, [r1, #20]
 8005c80:	f421 7140 	bic.w	r1, r1, #768	@ 0x300
 8005c84:	69a2      	ldr	r2, [r4, #24]
 8005c86:	4311      	orrs	r1, r2
 8005c88:	6822      	ldr	r2, [r4, #0]
 8005c8a:	6151      	str	r1, [r2, #20]
 8005c8c:	4a2d      	ldr	r2, [pc, #180]	@ (8005d44 <UART_SetConfig+0xf8>)
 8005c8e:	6821      	ldr	r1, [r4, #0]
 8005c90:	4291      	cmp	r1, r2
 8005c92:	d102      	bne.n	8005c9a <UART_SetConfig+0x4e>
 8005c94:	f7fe f9cc 	bl	8004030 <HAL_RCC_GetPCLK2Freq>
 8005c98:	e001      	b.n	8005c9e <UART_SetConfig+0x52>
 8005c9a:	f7fe f9b9 	bl	8004010 <HAL_RCC_GetPCLK1Freq>
 8005c9e:	eb00 01c0 	add.w	r1, r0, r0, lsl #3
 8005ca2:	eb01 1100 	add.w	r1, r1, r0, lsl #4
 8005ca6:	6862      	ldr	r2, [r4, #4]
 8005ca8:	0092      	lsls	r2, r2, #2
 8005caa:	fbb1 f1f2 	udiv	r1, r1, r2
 8005cae:	eb00 02c0 	add.w	r2, r0, r0, lsl #3
 8005cb2:	eb02 1200 	add.w	r2, r2, r0, lsl #4
 8005cb6:	6863      	ldr	r3, [r4, #4]
 8005cb8:	009b      	lsls	r3, r3, #2
 8005cba:	fbb2 f2f3 	udiv	r2, r2, r3
 8005cbe:	2364      	movs	r3, #100	@ 0x64
 8005cc0:	fbb2 f2f3 	udiv	r2, r2, r3
 8005cc4:	eb02 03c2 	add.w	r3, r2, r2, lsl #3
 8005cc8:	eb03 1202 	add.w	r2, r3, r2, lsl #4
 8005ccc:	eba1 0182 	sub.w	r1, r1, r2, lsl #2
 8005cd0:	2232      	movs	r2, #50	@ 0x32
 8005cd2:	eb02 1101 	add.w	r1, r2, r1, lsl #4
 8005cd6:	2264      	movs	r2, #100	@ 0x64
 8005cd8:	fbb1 f1f2 	udiv	r1, r1, r2
 8005cdc:	f001 01f0 	and.w	r1, r1, #240	@ 0xf0
 8005ce0:	eb00 02c0 	add.w	r2, r0, r0, lsl #3
 8005ce4:	eb02 1200 	add.w	r2, r2, r0, lsl #4
 8005ce8:	6863      	ldr	r3, [r4, #4]
 8005cea:	009b      	lsls	r3, r3, #2
 8005cec:	fbb2 f2f3 	udiv	r2, r2, r3
 8005cf0:	2364      	movs	r3, #100	@ 0x64
 8005cf2:	fbb2 f2f3 	udiv	r2, r2, r3
 8005cf6:	eb01 1202 	add.w	r2, r1, r2, lsl #4
 8005cfa:	eb00 01c0 	add.w	r1, r0, r0, lsl #3
 8005cfe:	eb01 1100 	add.w	r1, r1, r0, lsl #4
 8005d02:	6863      	ldr	r3, [r4, #4]
 8005d04:	009b      	lsls	r3, r3, #2
 8005d06:	fbb1 f1f3 	udiv	r1, r1, r3
 8005d0a:	eb00 03c0 	add.w	r3, r0, r0, lsl #3
 8005d0e:	eb03 1300 	add.w	r3, r3, r0, lsl #4
 8005d12:	6866      	ldr	r6, [r4, #4]
 8005d14:	00b6      	lsls	r6, r6, #2
 8005d16:	fbb3 f3f6 	udiv	r3, r3, r6
 8005d1a:	2664      	movs	r6, #100	@ 0x64
 8005d1c:	fbb3 f3f6 	udiv	r3, r3, r6
 8005d20:	eb03 06c3 	add.w	r6, r3, r3, lsl #3
 8005d24:	eb06 1303 	add.w	r3, r6, r3, lsl #4
 8005d28:	eba1 0183 	sub.w	r1, r1, r3, lsl #2
 8005d2c:	2332      	movs	r3, #50	@ 0x32
 8005d2e:	eb03 1101 	add.w	r1, r3, r1, lsl #4
 8005d32:	2364      	movs	r3, #100	@ 0x64
 8005d34:	fbb1 f1f3 	udiv	r1, r1, r3
 8005d38:	f001 010f 	and.w	r1, r1, #15
 8005d3c:	4411      	add	r1, r2
 8005d3e:	6822      	ldr	r2, [r4, #0]
 8005d40:	6091      	str	r1, [r2, #8]
 8005d42:	bd70      	pop	{r4, r5, r6, pc}
 8005d44:	40013800 	.word	0x40013800

08005d48 <UART_Start_Receive_DMA>:
 8005d48:	b577      	push	{r0, r1, r2, r4, r5, r6, lr}
 8005d4a:	b081      	sub	sp, #4
 8005d4c:	4604      	mov	r4, r0
 8005d4e:	4615      	mov	r5, r2
 8005d50:	9802      	ldr	r0, [sp, #8]
 8005d52:	62a0      	str	r0, [r4, #40]	@ 0x28
 8005d54:	85a5      	strh	r5, [r4, #44]	@ 0x2c
 8005d56:	2000      	movs	r0, #0
 8005d58:	6460      	str	r0, [r4, #68]	@ 0x44
 8005d5a:	2022      	movs	r0, #34	@ 0x22
 8005d5c:	f884 0042 	strb.w	r0, [r4, #66]	@ 0x42
 8005d60:	4828      	ldr	r0, [pc, #160]	@ (8005e04 <UART_Start_Receive_DMA+0xbc>)
 8005d62:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8005d64:	6288      	str	r0, [r1, #40]	@ 0x28
 8005d66:	4828      	ldr	r0, [pc, #160]	@ (8005e08 <UART_Start_Receive_DMA+0xc0>)
 8005d68:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8005d6a:	62c8      	str	r0, [r1, #44]	@ 0x2c
 8005d6c:	4827      	ldr	r0, [pc, #156]	@ (8005e0c <UART_Start_Receive_DMA+0xc4>)
 8005d6e:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8005d70:	6308      	str	r0, [r1, #48]	@ 0x30
 8005d72:	2000      	movs	r0, #0
 8005d74:	6be1      	ldr	r1, [r4, #60]	@ 0x3c
 8005d76:	6348      	str	r0, [r1, #52]	@ 0x34
 8005d78:	ae02      	add	r6, sp, #8
 8005d7a:	6832      	ldr	r2, [r6, #0]
 8005d7c:	6823      	ldr	r3, [r4, #0]
 8005d7e:	1d19      	adds	r1, r3, #4
 8005d80:	462b      	mov	r3, r5
 8005d82:	6be0      	ldr	r0, [r4, #60]	@ 0x3c
 8005d84:	f7fc f9f0 	bl	8002168 <HAL_DMA_Start_IT>
 8005d88:	bf00      	nop
 8005d8a:	2000      	movs	r0, #0
 8005d8c:	9000      	str	r0, [sp, #0]
 8005d8e:	6820      	ldr	r0, [r4, #0]
 8005d90:	6800      	ldr	r0, [r0, #0]
 8005d92:	9000      	str	r0, [sp, #0]
 8005d94:	6820      	ldr	r0, [r4, #0]
 8005d96:	6840      	ldr	r0, [r0, #4]
 8005d98:	9000      	str	r0, [sp, #0]
 8005d9a:	bf00      	nop
 8005d9c:	bf00      	nop
 8005d9e:	6920      	ldr	r0, [r4, #16]
 8005da0:	b170      	cbz	r0, 8005dc0 <UART_Start_Receive_DMA+0x78>
 8005da2:	bf00      	nop
 8005da4:	bf00      	nop
 8005da6:	6821      	ldr	r1, [r4, #0]
 8005da8:	310c      	adds	r1, #12
 8005daa:	e851 1f00 	ldrex	r1, [r1]
 8005dae:	f441 7080 	orr.w	r0, r1, #256	@ 0x100
 8005db2:	6821      	ldr	r1, [r4, #0]
 8005db4:	310c      	adds	r1, #12
 8005db6:	e841 0200 	strex	r2, r0, [r1]
 8005dba:	2a00      	cmp	r2, #0
 8005dbc:	d1f3      	bne.n	8005da6 <UART_Start_Receive_DMA+0x5e>
 8005dbe:	bf00      	nop
 8005dc0:	bf00      	nop
 8005dc2:	bf00      	nop
 8005dc4:	6821      	ldr	r1, [r4, #0]
 8005dc6:	3114      	adds	r1, #20
 8005dc8:	e851 1f00 	ldrex	r1, [r1]
 8005dcc:	f041 0001 	orr.w	r0, r1, #1
 8005dd0:	6821      	ldr	r1, [r4, #0]
 8005dd2:	3114      	adds	r1, #20
 8005dd4:	e841 0200 	strex	r2, r0, [r1]
 8005dd8:	2a00      	cmp	r2, #0
 8005dda:	d1f3      	bne.n	8005dc4 <UART_Start_Receive_DMA+0x7c>
 8005ddc:	bf00      	nop
 8005dde:	bf00      	nop
 8005de0:	bf00      	nop
 8005de2:	6821      	ldr	r1, [r4, #0]
 8005de4:	3114      	adds	r1, #20
 8005de6:	e851 1f00 	ldrex	r1, [r1]
 8005dea:	f041 0040 	orr.w	r0, r1, #64	@ 0x40
 8005dee:	6821      	ldr	r1, [r4, #0]
 8005df0:	3114      	adds	r1, #20
 8005df2:	e841 0200 	strex	r2, r0, [r1]
 8005df6:	2a00      	cmp	r2, #0
 8005df8:	d1f3      	bne.n	8005de2 <UART_Start_Receive_DMA+0x9a>
 8005dfa:	bf00      	nop
 8005dfc:	2000      	movs	r0, #0
 8005dfe:	b004      	add	sp, #16
 8005e00:	bd70      	pop	{r4, r5, r6, pc}
 8005e02:	0000      	.short	0x0000
 8005e04:	080058bb 	.word	0x080058bb
 8005e08:	080059a7 	.word	0x080059a7
 8005e0c:	0800586b 	.word	0x0800586b

08005e10 <UART_Start_Receive_IT>:
 8005e10:	b510      	push	{r4, lr}
 8005e12:	4603      	mov	r3, r0
 8005e14:	6299      	str	r1, [r3, #40]	@ 0x28
 8005e16:	859a      	strh	r2, [r3, #44]	@ 0x2c
 8005e18:	85da      	strh	r2, [r3, #46]	@ 0x2e
 8005e1a:	2000      	movs	r0, #0
 8005e1c:	6458      	str	r0, [r3, #68]	@ 0x44
 8005e1e:	2022      	movs	r0, #34	@ 0x22
 8005e20:	f883 0042 	strb.w	r0, [r3, #66]	@ 0x42
 8005e24:	6918      	ldr	r0, [r3, #16]
 8005e26:	b128      	cbz	r0, 8005e34 <UART_Start_Receive_IT+0x24>
 8005e28:	6818      	ldr	r0, [r3, #0]
 8005e2a:	68c0      	ldr	r0, [r0, #12]
 8005e2c:	f440 7080 	orr.w	r0, r0, #256	@ 0x100
 8005e30:	681c      	ldr	r4, [r3, #0]
 8005e32:	60e0      	str	r0, [r4, #12]
 8005e34:	6818      	ldr	r0, [r3, #0]
 8005e36:	6940      	ldr	r0, [r0, #20]
 8005e38:	f040 0001 	orr.w	r0, r0, #1
 8005e3c:	681c      	ldr	r4, [r3, #0]
 8005e3e:	6160      	str	r0, [r4, #20]
 8005e40:	6818      	ldr	r0, [r3, #0]
 8005e42:	68c0      	ldr	r0, [r0, #12]
 8005e44:	f040 0020 	orr.w	r0, r0, #32
 8005e48:	681c      	ldr	r4, [r3, #0]
 8005e4a:	60e0      	str	r0, [r4, #12]
 8005e4c:	2000      	movs	r0, #0
 8005e4e:	bd10      	pop	{r4, pc}

08005e50 <UART_Transmit_IT>:
 8005e50:	4601      	mov	r1, r0
 8005e52:	f891 0041 	ldrb.w	r0, [r1, #65]	@ 0x41
 8005e56:	2821      	cmp	r0, #33	@ 0x21
 8005e58:	d128      	bne.n	8005eac <UART_Transmit_IT+0x5c>
 8005e5a:	6888      	ldr	r0, [r1, #8]
 8005e5c:	f5b0 5f80 	cmp.w	r0, #4096	@ 0x1000
 8005e60:	d10b      	bne.n	8005e7a <UART_Transmit_IT+0x2a>
 8005e62:	6908      	ldr	r0, [r1, #16]
 8005e64:	b948      	cbnz	r0, 8005e7a <UART_Transmit_IT+0x2a>
 8005e66:	6a0a      	ldr	r2, [r1, #32]
 8005e68:	8810      	ldrh	r0, [r2, #0]
 8005e6a:	f3c0 0008 	ubfx	r0, r0, #0, #9
 8005e6e:	680b      	ldr	r3, [r1, #0]
 8005e70:	6058      	str	r0, [r3, #4]
 8005e72:	6a08      	ldr	r0, [r1, #32]
 8005e74:	1c80      	adds	r0, r0, #2
 8005e76:	6208      	str	r0, [r1, #32]
 8005e78:	e005      	b.n	8005e86 <UART_Transmit_IT+0x36>
 8005e7a:	6a0b      	ldr	r3, [r1, #32]
 8005e7c:	1c58      	adds	r0, r3, #1
 8005e7e:	6208      	str	r0, [r1, #32]
 8005e80:	7818      	ldrb	r0, [r3, #0]
 8005e82:	680b      	ldr	r3, [r1, #0]
 8005e84:	6058      	str	r0, [r3, #4]
 8005e86:	8cc8      	ldrh	r0, [r1, #38]	@ 0x26
 8005e88:	1e40      	subs	r0, r0, #1
 8005e8a:	b280      	uxth	r0, r0
 8005e8c:	84c8      	strh	r0, [r1, #38]	@ 0x26
 8005e8e:	b958      	cbnz	r0, 8005ea8 <UART_Transmit_IT+0x58>
 8005e90:	6808      	ldr	r0, [r1, #0]
 8005e92:	68c0      	ldr	r0, [r0, #12]
 8005e94:	f020 0080 	bic.w	r0, r0, #128	@ 0x80
 8005e98:	680b      	ldr	r3, [r1, #0]
 8005e9a:	60d8      	str	r0, [r3, #12]
 8005e9c:	6808      	ldr	r0, [r1, #0]
 8005e9e:	68c0      	ldr	r0, [r0, #12]
 8005ea0:	f040 0040 	orr.w	r0, r0, #64	@ 0x40
 8005ea4:	680b      	ldr	r3, [r1, #0]
 8005ea6:	60d8      	str	r0, [r3, #12]
 8005ea8:	2000      	movs	r0, #0
 8005eaa:	4770      	bx	lr
 8005eac:	2002      	movs	r0, #2
 8005eae:	e7fc      	b.n	8005eaa <UART_Transmit_IT+0x5a>

08005eb0 <UART_WaitOnFlagUntilTimeout>:
 8005eb0:	e92d 43f8 	stmdb	sp!, {r3, r4, r5, r6, r7, r8, r9, lr}
 8005eb4:	4604      	mov	r4, r0
 8005eb6:	460d      	mov	r5, r1
 8005eb8:	4617      	mov	r7, r2
 8005eba:	4698      	mov	r8, r3
 8005ebc:	9e08      	ldr	r6, [sp, #32]
 8005ebe:	e031      	b.n	8005f24 <UART_WaitOnFlagUntilTimeout+0x74>
 8005ec0:	1c70      	adds	r0, r6, #1
 8005ec2:	b370      	cbz	r0, 8005f22 <UART_WaitOnFlagUntilTimeout+0x72>
 8005ec4:	f7fd f8d8 	bl	8003078 <HAL_GetTick>
 8005ec8:	eba0 0008 	sub.w	r0, r0, r8
 8005ecc:	42b0      	cmp	r0, r6
 8005ece:	d800      	bhi.n	8005ed2 <UART_WaitOnFlagUntilTimeout+0x22>
 8005ed0:	b916      	cbnz	r6, 8005ed8 <UART_WaitOnFlagUntilTimeout+0x28>
 8005ed2:	2003      	movs	r0, #3
 8005ed4:	e8bd 83f8 	ldmia.w	sp!, {r3, r4, r5, r6, r7, r8, r9, pc}
 8005ed8:	6820      	ldr	r0, [r4, #0]
 8005eda:	68c0      	ldr	r0, [r0, #12]
 8005edc:	f000 0004 	and.w	r0, r0, #4
 8005ee0:	b1f8      	cbz	r0, 8005f22 <UART_WaitOnFlagUntilTimeout+0x72>
 8005ee2:	2d80      	cmp	r5, #128	@ 0x80
 8005ee4:	d01e      	beq.n	8005f24 <UART_WaitOnFlagUntilTimeout+0x74>
 8005ee6:	2d40      	cmp	r5, #64	@ 0x40
 8005ee8:	d01c      	beq.n	8005f24 <UART_WaitOnFlagUntilTimeout+0x74>
 8005eea:	6820      	ldr	r0, [r4, #0]
 8005eec:	6800      	ldr	r0, [r0, #0]
 8005eee:	f3c0 00c0 	ubfx	r0, r0, #3, #1
 8005ef2:	b1b0      	cbz	r0, 8005f22 <UART_WaitOnFlagUntilTimeout+0x72>
 8005ef4:	bf00      	nop
 8005ef6:	2000      	movs	r0, #0
 8005ef8:	9000      	str	r0, [sp, #0]
 8005efa:	6820      	ldr	r0, [r4, #0]
 8005efc:	6800      	ldr	r0, [r0, #0]
 8005efe:	9000      	str	r0, [sp, #0]
 8005f00:	6820      	ldr	r0, [r4, #0]
 8005f02:	6840      	ldr	r0, [r0, #4]
 8005f04:	9000      	str	r0, [sp, #0]
 8005f06:	bf00      	nop
 8005f08:	bf00      	nop
 8005f0a:	4620      	mov	r0, r4
 8005f0c:	f7ff fdc6 	bl	8005a9c <UART_EndRxTransfer>
 8005f10:	2008      	movs	r0, #8
 8005f12:	6460      	str	r0, [r4, #68]	@ 0x44
 8005f14:	bf00      	nop
 8005f16:	2000      	movs	r0, #0
 8005f18:	f884 0040 	strb.w	r0, [r4, #64]	@ 0x40
 8005f1c:	bf00      	nop
 8005f1e:	2001      	movs	r0, #1
 8005f20:	e7d8      	b.n	8005ed4 <UART_WaitOnFlagUntilTimeout+0x24>
 8005f22:	e7ff      	b.n	8005f24 <UART_WaitOnFlagUntilTimeout+0x74>
 8005f24:	6820      	ldr	r0, [r4, #0]
 8005f26:	6800      	ldr	r0, [r0, #0]
 8005f28:	4028      	ands	r0, r5
 8005f2a:	42a8      	cmp	r0, r5
 8005f2c:	d101      	bne.n	8005f32 <UART_WaitOnFlagUntilTimeout+0x82>
 8005f2e:	2001      	movs	r0, #1
 8005f30:	e000      	b.n	8005f34 <UART_WaitOnFlagUntilTimeout+0x84>
 8005f32:	2000      	movs	r0, #0
 8005f34:	42b8      	cmp	r0, r7
 8005f36:	d0c3      	beq.n	8005ec0 <UART_WaitOnFlagUntilTimeout+0x10>
 8005f38:	2000      	movs	r0, #0
 8005f3a:	e7cb      	b.n	8005ed4 <UART_WaitOnFlagUntilTimeout+0x24>

08005f3c <UsageFault_Handler>:
 8005f3c:	bf00      	nop
 8005f3e:	e7fe      	b.n	8005f3e <UsageFault_Handler+0x2>

08005f40 <__0printf$8>:
 8005f40:	b40f      	push	{r0, r1, r2, r3}
 8005f42:	4b05      	ldr	r3, [pc, #20]	@ (8005f58 <__0printf$8+0x18>)
 8005f44:	b510      	push	{r4, lr}
 8005f46:	a903      	add	r1, sp, #12
 8005f48:	4a04      	ldr	r2, [pc, #16]	@ (8005f5c <__0printf$8+0x1c>)
 8005f4a:	9802      	ldr	r0, [sp, #8]
 8005f4c:	f000 f834 	bl	8005fb8 <_printf_core>
 8005f50:	bc10      	pop	{r4}
 8005f52:	f85d fb14 	ldr.w	pc, [sp], #20
 8005f56:	0000      	.short	0x0000
 8005f58:	0800646d 	.word	0x0800646d
 8005f5c:	2000001c 	.word	0x2000001c

08005f60 <__NVIC_GetPriorityGrouping>:
 8005f60:	4802      	ldr	r0, [pc, #8]	@ (8005f6c <__NVIC_GetPriorityGrouping+0xc>)
 8005f62:	6800      	ldr	r0, [r0, #0]
 8005f64:	f3c0 2002 	ubfx	r0, r0, #8, #3
 8005f68:	4770      	bx	lr
 8005f6a:	0000      	.short	0x0000
 8005f6c:	e000ed0c 	.word	0xe000ed0c

08005f70 <__NVIC_SetPriority>:
 8005f70:	b510      	push	{r4, lr}
 8005f72:	2800      	cmp	r0, #0
 8005f74:	db04      	blt.n	8005f80 <__NVIC_SetPriority+0x10>
 8005f76:	070a      	lsls	r2, r1, #28
 8005f78:	0e13      	lsrs	r3, r2, #24
 8005f7a:	4a05      	ldr	r2, [pc, #20]	@ (8005f90 <__NVIC_SetPriority+0x20>)
 8005f7c:	5413      	strb	r3, [r2, r0]
 8005f7e:	e006      	b.n	8005f8e <__NVIC_SetPriority+0x1e>
 8005f80:	070a      	lsls	r2, r1, #28
 8005f82:	0e14      	lsrs	r4, r2, #24
 8005f84:	4a03      	ldr	r2, [pc, #12]	@ (8005f94 <__NVIC_SetPriority+0x24>)
 8005f86:	f000 030f 	and.w	r3, r0, #15
 8005f8a:	1f1b      	subs	r3, r3, #4
 8005f8c:	54d4      	strb	r4, [r2, r3]
 8005f8e:	bd10      	pop	{r4, pc}
 8005f90:	e000e400 	.word	0xe000e400
 8005f94:	e000ed18 	.word	0xe000ed18

08005f98 <__scatterload_copy>:
 8005f98:	e002      	b.n	8005fa0 <__scatterload_copy+0x8>
 8005f9a:	c808      	ldmia	r0!, {r3}
 8005f9c:	1f12      	subs	r2, r2, #4
 8005f9e:	c108      	stmia	r1!, {r3}
 8005fa0:	2a00      	cmp	r2, #0
 8005fa2:	d1fa      	bne.n	8005f9a <__scatterload_copy+0x2>
 8005fa4:	4770      	bx	lr

08005fa6 <__scatterload_null>:
 8005fa6:	4770      	bx	lr

08005fa8 <__scatterload_zeroinit>:
 8005fa8:	2000      	movs	r0, #0
 8005faa:	e001      	b.n	8005fb0 <__scatterload_zeroinit+0x8>
 8005fac:	c101      	stmia	r1!, {r0}
 8005fae:	1f12      	subs	r2, r2, #4
 8005fb0:	2a00      	cmp	r2, #0
 8005fb2:	d1fb      	bne.n	8005fac <__scatterload_zeroinit+0x4>
 8005fb4:	4770      	bx	lr
	...

08005fb8 <_printf_core>:
 8005fb8:	e92d 4fff 	stmdb	sp!, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
 8005fbc:	b08d      	sub	sp, #52	@ 0x34
 8005fbe:	460f      	mov	r7, r1
 8005fc0:	4605      	mov	r5, r0
 8005fc2:	2600      	movs	r6, #0
 8005fc4:	e006      	b.n	8005fd4 <_printf_core+0x1c>
 8005fc6:	2825      	cmp	r0, #37	@ 0x25
 8005fc8:	d00b      	beq.n	8005fe2 <_printf_core+0x2a>
 8005fca:	e9dd 120f 	ldrd	r1, r2, [sp, #60]	@ 0x3c
 8005fce:	4790      	blx	r2
 8005fd0:	1c6d      	adds	r5, r5, #1
 8005fd2:	1c76      	adds	r6, r6, #1
 8005fd4:	7828      	ldrb	r0, [r5, #0]
 8005fd6:	2800      	cmp	r0, #0
 8005fd8:	d1f5      	bne.n	8005fc6 <_printf_core+0xe>
 8005fda:	b011      	add	sp, #68	@ 0x44
 8005fdc:	4630      	mov	r0, r6
 8005fde:	e8bd 8ff0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, pc}
 8005fe2:	2400      	movs	r4, #0
 8005fe4:	46a2      	mov	sl, r4
 8005fe6:	46a1      	mov	r9, r4
 8005fe8:	2201      	movs	r2, #1
 8005fea:	49e9      	ldr	r1, [pc, #932]	@ (8006390 <_printf_core+0x3d8>)
 8005fec:	e000      	b.n	8005ff0 <_printf_core+0x38>
 8005fee:	4304      	orrs	r4, r0
 8005ff0:	f815 3f01 	ldrb.w	r3, [r5, #1]!
 8005ff4:	3b20      	subs	r3, #32
 8005ff6:	fa02 f003 	lsl.w	r0, r2, r3
 8005ffa:	4208      	tst	r0, r1
 8005ffc:	d1f7      	bne.n	8005fee <_printf_core+0x36>
 8005ffe:	7828      	ldrb	r0, [r5, #0]
 8006000:	282a      	cmp	r0, #42	@ 0x2a
 8006002:	d010      	beq.n	8006026 <_printf_core+0x6e>
 8006004:	f06f 022f 	mvn.w	r2, #47	@ 0x2f
 8006008:	7828      	ldrb	r0, [r5, #0]
 800600a:	f1a0 0130 	sub.w	r1, r0, #48	@ 0x30
 800600e:	2909      	cmp	r1, #9
 8006010:	d814      	bhi.n	800603c <_printf_core+0x84>
 8006012:	eb0a 018a 	add.w	r1, sl, sl, lsl #2
 8006016:	eb02 0141 	add.w	r1, r2, r1, lsl #1
 800601a:	f044 0402 	orr.w	r4, r4, #2
 800601e:	eb00 0a01 	add.w	sl, r0, r1
 8006022:	1c6d      	adds	r5, r5, #1
 8006024:	e7f0      	b.n	8006008 <_printf_core+0x50>
 8006026:	cf01      	ldmia	r7!, {r0}
 8006028:	ea5f 0a00 	movs.w	sl, r0
 800602c:	d503      	bpl.n	8006036 <_printf_core+0x7e>
 800602e:	f444 5400 	orr.w	r4, r4, #8192	@ 0x2000
 8006032:	f1ca 0a00 	rsb	sl, sl, #0
 8006036:	f044 0402 	orr.w	r4, r4, #2
 800603a:	1c6d      	adds	r5, r5, #1
 800603c:	7828      	ldrb	r0, [r5, #0]
 800603e:	282e      	cmp	r0, #46	@ 0x2e
 8006040:	d117      	bne.n	8006072 <_printf_core+0xba>
 8006042:	f815 0f01 	ldrb.w	r0, [r5, #1]!
 8006046:	f044 0404 	orr.w	r4, r4, #4
 800604a:	282a      	cmp	r0, #42	@ 0x2a
 800604c:	d00e      	beq.n	800606c <_printf_core+0xb4>
 800604e:	f06f 022f 	mvn.w	r2, #47	@ 0x2f
 8006052:	7828      	ldrb	r0, [r5, #0]
 8006054:	f1a0 0130 	sub.w	r1, r0, #48	@ 0x30
 8006058:	2909      	cmp	r1, #9
 800605a:	d80a      	bhi.n	8006072 <_printf_core+0xba>
 800605c:	eb09 0189 	add.w	r1, r9, r9, lsl #2
 8006060:	eb02 0141 	add.w	r1, r2, r1, lsl #1
 8006064:	eb00 0901 	add.w	r9, r0, r1
 8006068:	1c6d      	adds	r5, r5, #1
 800606a:	e7f2      	b.n	8006052 <_printf_core+0x9a>
 800606c:	f857 9b04 	ldr.w	r9, [r7], #4
 8006070:	1c6d      	adds	r5, r5, #1
 8006072:	7828      	ldrb	r0, [r5, #0]
 8006074:	286c      	cmp	r0, #108	@ 0x6c
 8006076:	d00f      	beq.n	8006098 <_printf_core+0xe0>
 8006078:	dc06      	bgt.n	8006088 <_printf_core+0xd0>
 800607a:	284c      	cmp	r0, #76	@ 0x4c
 800607c:	d017      	beq.n	80060ae <_printf_core+0xf6>
 800607e:	2868      	cmp	r0, #104	@ 0x68
 8006080:	d00d      	beq.n	800609e <_printf_core+0xe6>
 8006082:	286a      	cmp	r0, #106	@ 0x6a
 8006084:	d114      	bne.n	80060b0 <_printf_core+0xf8>
 8006086:	e004      	b.n	8006092 <_printf_core+0xda>
 8006088:	2874      	cmp	r0, #116	@ 0x74
 800608a:	d010      	beq.n	80060ae <_printf_core+0xf6>
 800608c:	287a      	cmp	r0, #122	@ 0x7a
 800608e:	d10f      	bne.n	80060b0 <_printf_core+0xf8>
 8006090:	e00d      	b.n	80060ae <_printf_core+0xf6>
 8006092:	f444 1400 	orr.w	r4, r4, #2097152	@ 0x200000
 8006096:	e00a      	b.n	80060ae <_printf_core+0xf6>
 8006098:	f444 1480 	orr.w	r4, r4, #1048576	@ 0x100000
 800609c:	e001      	b.n	80060a2 <_printf_core+0xea>
 800609e:	f444 1440 	orr.w	r4, r4, #3145728	@ 0x300000
 80060a2:	7869      	ldrb	r1, [r5, #1]
 80060a4:	4281      	cmp	r1, r0
 80060a6:	d102      	bne.n	80060ae <_printf_core+0xf6>
 80060a8:	f504 1480 	add.w	r4, r4, #1048576	@ 0x100000
 80060ac:	1c6d      	adds	r5, r5, #1
 80060ae:	1c6d      	adds	r5, r5, #1
 80060b0:	7828      	ldrb	r0, [r5, #0]
 80060b2:	286e      	cmp	r0, #110	@ 0x6e
 80060b4:	d01e      	beq.n	80060f4 <_printf_core+0x13c>
 80060b6:	dc0c      	bgt.n	80060d2 <_printf_core+0x11a>
 80060b8:	2863      	cmp	r0, #99	@ 0x63
 80060ba:	d030      	beq.n	800611e <_printf_core+0x166>
 80060bc:	dc04      	bgt.n	80060c8 <_printf_core+0x110>
 80060be:	2800      	cmp	r0, #0
 80060c0:	d08b      	beq.n	8005fda <_printf_core+0x22>
 80060c2:	2858      	cmp	r0, #88	@ 0x58
 80060c4:	d111      	bne.n	80060ea <_printf_core+0x132>
 80060c6:	e09f      	b.n	8006208 <_printf_core+0x250>
 80060c8:	2864      	cmp	r0, #100	@ 0x64
 80060ca:	d067      	beq.n	800619c <_printf_core+0x1e4>
 80060cc:	2869      	cmp	r0, #105	@ 0x69
 80060ce:	d10c      	bne.n	80060ea <_printf_core+0x132>
 80060d0:	e064      	b.n	800619c <_printf_core+0x1e4>
 80060d2:	2873      	cmp	r0, #115	@ 0x73
 80060d4:	d02d      	beq.n	8006132 <_printf_core+0x17a>
 80060d6:	dc04      	bgt.n	80060e2 <_printf_core+0x12a>
 80060d8:	286f      	cmp	r0, #111	@ 0x6f
 80060da:	d072      	beq.n	80061c2 <_printf_core+0x20a>
 80060dc:	2870      	cmp	r0, #112	@ 0x70
 80060de:	d104      	bne.n	80060ea <_printf_core+0x132>
 80060e0:	e094      	b.n	800620c <_printf_core+0x254>
 80060e2:	2875      	cmp	r0, #117	@ 0x75
 80060e4:	d06e      	beq.n	80061c4 <_printf_core+0x20c>
 80060e6:	2878      	cmp	r0, #120	@ 0x78
 80060e8:	d06d      	beq.n	80061c6 <_printf_core+0x20e>
 80060ea:	e9dd 120f 	ldrd	r1, r2, [sp, #60]	@ 0x3c
 80060ee:	4790      	blx	r2
 80060f0:	1c76      	adds	r6, r6, #1
 80060f2:	e14b      	b.n	800638c <_printf_core+0x3d4>
 80060f4:	f3c4 5002 	ubfx	r0, r4, #20, #3
 80060f8:	2802      	cmp	r0, #2
 80060fa:	d006      	beq.n	800610a <_printf_core+0x152>
 80060fc:	2803      	cmp	r0, #3
 80060fe:	d009      	beq.n	8006114 <_printf_core+0x15c>
 8006100:	2804      	cmp	r0, #4
 8006102:	cf01      	ldmia	r7!, {r0}
 8006104:	d009      	beq.n	800611a <_printf_core+0x162>
 8006106:	6006      	str	r6, [r0, #0]
 8006108:	e140      	b.n	800638c <_printf_core+0x3d4>
 800610a:	cf01      	ldmia	r7!, {r0}
 800610c:	17f1      	asrs	r1, r6, #31
 800610e:	e9c0 6100 	strd	r6, r1, [r0]
 8006112:	e13b      	b.n	800638c <_printf_core+0x3d4>
 8006114:	cf01      	ldmia	r7!, {r0}
 8006116:	8006      	strh	r6, [r0, #0]
 8006118:	e138      	b.n	800638c <_printf_core+0x3d4>
 800611a:	7006      	strb	r6, [r0, #0]
 800611c:	e136      	b.n	800638c <_printf_core+0x3d4>
 800611e:	f817 0b04 	ldrb.w	r0, [r7], #4
 8006122:	f88d 0000 	strb.w	r0, [sp]
 8006126:	2000      	movs	r0, #0
 8006128:	f88d 0001 	strb.w	r0, [sp, #1]
 800612c:	46eb      	mov	fp, sp
 800612e:	2001      	movs	r0, #1
 8006130:	e003      	b.n	800613a <_printf_core+0x182>
 8006132:	f857 bb04 	ldr.w	fp, [r7], #4
 8006136:	f04f 30ff 	mov.w	r0, #4294967295
 800613a:	0761      	lsls	r1, r4, #29
 800613c:	f04f 0100 	mov.w	r1, #0
 8006140:	d402      	bmi.n	8006148 <_printf_core+0x190>
 8006142:	e00d      	b.n	8006160 <_printf_core+0x1a8>
 8006144:	f108 0101 	add.w	r1, r8, #1
 8006148:	4688      	mov	r8, r1
 800614a:	4549      	cmp	r1, r9
 800614c:	da0f      	bge.n	800616e <_printf_core+0x1b6>
 800614e:	4580      	cmp	r8, r0
 8006150:	dbf8      	blt.n	8006144 <_printf_core+0x18c>
 8006152:	f81b 1008 	ldrb.w	r1, [fp, r8]
 8006156:	2900      	cmp	r1, #0
 8006158:	d1f4      	bne.n	8006144 <_printf_core+0x18c>
 800615a:	e008      	b.n	800616e <_printf_core+0x1b6>
 800615c:	f108 0101 	add.w	r1, r8, #1
 8006160:	4688      	mov	r8, r1
 8006162:	4281      	cmp	r1, r0
 8006164:	dbfa      	blt.n	800615c <_printf_core+0x1a4>
 8006166:	f81b 1008 	ldrb.w	r1, [fp, r8]
 800616a:	2900      	cmp	r1, #0
 800616c:	d1f6      	bne.n	800615c <_printf_core+0x1a4>
 800616e:	e9dd 230f 	ldrd	r2, r3, [sp, #60]	@ 0x3c
 8006172:	ebaa 0008 	sub.w	r0, sl, r8
 8006176:	4681      	mov	r9, r0
 8006178:	4621      	mov	r1, r4
 800617a:	f000 f931 	bl	80063e0 <_printf_pre_padding>
 800617e:	4430      	add	r0, r6
 8006180:	eb00 0608 	add.w	r6, r0, r8
 8006184:	e004      	b.n	8006190 <_printf_core+0x1d8>
 8006186:	e9dd 120f 	ldrd	r1, r2, [sp, #60]	@ 0x3c
 800618a:	f81b 0b01 	ldrb.w	r0, [fp], #1
 800618e:	4790      	blx	r2
 8006190:	f1b8 0801 	subs.w	r8, r8, #1
 8006194:	d2f7      	bcs.n	8006186 <_printf_core+0x1ce>
 8006196:	4621      	mov	r1, r4
 8006198:	4648      	mov	r0, r9
 800619a:	e0f2      	b.n	8006382 <_printf_core+0x3ca>
 800619c:	210a      	movs	r1, #10
 800619e:	f3c4 5202 	ubfx	r2, r4, #20, #3
 80061a2:	f04f 0b00 	mov.w	fp, #0
 80061a6:	9108      	str	r1, [sp, #32]
 80061a8:	2a02      	cmp	r2, #2
 80061aa:	d004      	beq.n	80061b6 <_printf_core+0x1fe>
 80061ac:	cf01      	ldmia	r7!, {r0}
 80061ae:	17c1      	asrs	r1, r0, #31
 80061b0:	2a03      	cmp	r2, #3
 80061b2:	d009      	beq.n	80061c8 <_printf_core+0x210>
 80061b4:	e00a      	b.n	80061cc <_printf_core+0x214>
 80061b6:	1dff      	adds	r7, r7, #7
 80061b8:	f027 0707 	bic.w	r7, r7, #7
 80061bc:	e8f7 0102 	ldrd	r0, r1, [r7], #8
 80061c0:	e008      	b.n	80061d4 <_printf_core+0x21c>
 80061c2:	e02c      	b.n	800621e <_printf_core+0x266>
 80061c4:	e01e      	b.n	8006204 <_printf_core+0x24c>
 80061c6:	e01f      	b.n	8006208 <_printf_core+0x250>
 80061c8:	b200      	sxth	r0, r0
 80061ca:	17c1      	asrs	r1, r0, #31
 80061cc:	2a04      	cmp	r2, #4
 80061ce:	d101      	bne.n	80061d4 <_printf_core+0x21c>
 80061d0:	b240      	sxtb	r0, r0
 80061d2:	17c1      	asrs	r1, r0, #31
 80061d4:	1e02      	subs	r2, r0, #0
 80061d6:	f171 0200 	sbcs.w	r2, r1, #0
 80061da:	da06      	bge.n	80061ea <_printf_core+0x232>
 80061dc:	2300      	movs	r3, #0
 80061de:	ebd0 0003 	rsbs	r0, r0, r3
 80061e2:	eb63 0101 	sbc.w	r1, r3, r1
 80061e6:	222d      	movs	r2, #45	@ 0x2d
 80061e8:	e002      	b.n	80061f0 <_printf_core+0x238>
 80061ea:	0522      	lsls	r2, r4, #20
 80061ec:	d504      	bpl.n	80061f8 <_printf_core+0x240>
 80061ee:	222b      	movs	r2, #43	@ 0x2b
 80061f0:	f88d 2024 	strb.w	r2, [sp, #36]	@ 0x24
 80061f4:	2201      	movs	r2, #1
 80061f6:	e003      	b.n	8006200 <_printf_core+0x248>
 80061f8:	07e2      	lsls	r2, r4, #31
 80061fa:	d001      	beq.n	8006200 <_printf_core+0x248>
 80061fc:	2220      	movs	r2, #32
 80061fe:	e7f7      	b.n	80061f0 <_printf_core+0x238>
 8006200:	4690      	mov	r8, r2
 8006202:	e053      	b.n	80062ac <_printf_core+0x2f4>
 8006204:	210a      	movs	r1, #10
 8006206:	e00b      	b.n	8006220 <_printf_core+0x268>
 8006208:	2110      	movs	r1, #16
 800620a:	e009      	b.n	8006220 <_printf_core+0x268>
 800620c:	2110      	movs	r1, #16
 800620e:	f04f 0b00 	mov.w	fp, #0
 8006212:	f044 0404 	orr.w	r4, r4, #4
 8006216:	f04f 0908 	mov.w	r9, #8
 800621a:	9108      	str	r1, [sp, #32]
 800621c:	e003      	b.n	8006226 <_printf_core+0x26e>
 800621e:	2108      	movs	r1, #8
 8006220:	f04f 0b00 	mov.w	fp, #0
 8006224:	9108      	str	r1, [sp, #32]
 8006226:	f3c4 5202 	ubfx	r2, r4, #20, #3
 800622a:	2a02      	cmp	r2, #2
 800622c:	d004      	beq.n	8006238 <_printf_core+0x280>
 800622e:	cf01      	ldmia	r7!, {r0}
 8006230:	2100      	movs	r1, #0
 8006232:	2a03      	cmp	r2, #3
 8006234:	d006      	beq.n	8006244 <_printf_core+0x28c>
 8006236:	e006      	b.n	8006246 <_printf_core+0x28e>
 8006238:	1dff      	adds	r7, r7, #7
 800623a:	f027 0707 	bic.w	r7, r7, #7
 800623e:	e8f7 0102 	ldrd	r0, r1, [r7], #8
 8006242:	e003      	b.n	800624c <_printf_core+0x294>
 8006244:	b280      	uxth	r0, r0
 8006246:	2a04      	cmp	r2, #4
 8006248:	d100      	bne.n	800624c <_printf_core+0x294>
 800624a:	b2c0      	uxtb	r0, r0
 800624c:	f04f 0800 	mov.w	r8, #0
 8006250:	0722      	lsls	r2, r4, #28
 8006252:	d52b      	bpl.n	80062ac <_printf_core+0x2f4>
 8006254:	782a      	ldrb	r2, [r5, #0]
 8006256:	2a70      	cmp	r2, #112	@ 0x70
 8006258:	d007      	beq.n	800626a <_printf_core+0x2b2>
 800625a:	f8dd c020 	ldr.w	ip, [sp, #32]
 800625e:	f08c 0c10 	eor.w	ip, ip, #16
 8006262:	ea5c 0c0b 	orrs.w	ip, ip, fp
 8006266:	d005      	beq.n	8006274 <_printf_core+0x2bc>
 8006268:	e00e      	b.n	8006288 <_printf_core+0x2d0>
 800626a:	2240      	movs	r2, #64	@ 0x40
 800626c:	f88d 2024 	strb.w	r2, [sp, #36]	@ 0x24
 8006270:	2201      	movs	r2, #1
 8006272:	e008      	b.n	8006286 <_printf_core+0x2ce>
 8006274:	ea50 0301 	orrs.w	r3, r0, r1
 8006278:	d006      	beq.n	8006288 <_printf_core+0x2d0>
 800627a:	2330      	movs	r3, #48	@ 0x30
 800627c:	f88d 3024 	strb.w	r3, [sp, #36]	@ 0x24
 8006280:	f88d 2025 	strb.w	r2, [sp, #37]	@ 0x25
 8006284:	2202      	movs	r2, #2
 8006286:	4690      	mov	r8, r2
 8006288:	9b08      	ldr	r3, [sp, #32]
 800628a:	f083 0308 	eor.w	r3, r3, #8
 800628e:	ea53 030b 	orrs.w	r3, r3, fp
 8006292:	d10b      	bne.n	80062ac <_printf_core+0x2f4>
 8006294:	ea50 0201 	orrs.w	r2, r0, r1
 8006298:	d101      	bne.n	800629e <_printf_core+0x2e6>
 800629a:	0762      	lsls	r2, r4, #29
 800629c:	d506      	bpl.n	80062ac <_printf_core+0x2f4>
 800629e:	2230      	movs	r2, #48	@ 0x30
 80062a0:	f88d 2024 	strb.w	r2, [sp, #36]	@ 0x24
 80062a4:	f04f 0801 	mov.w	r8, #1
 80062a8:	f1a9 0901 	sub.w	r9, r9, #1
 80062ac:	782a      	ldrb	r2, [r5, #0]
 80062ae:	2a58      	cmp	r2, #88	@ 0x58
 80062b0:	d004      	beq.n	80062bc <_printf_core+0x304>
 80062b2:	a238      	add	r2, pc, #224	@ (adr r2, 8006394 <_printf_core+0x3dc>)
 80062b4:	920b      	str	r2, [sp, #44]	@ 0x2c
 80062b6:	aa08      	add	r2, sp, #32
 80062b8:	920a      	str	r2, [sp, #40]	@ 0x28
 80062ba:	e00b      	b.n	80062d4 <_printf_core+0x31c>
 80062bc:	a23a      	add	r2, pc, #232	@ (adr r2, 80063a8 <_printf_core+0x3f0>)
 80062be:	e7f9      	b.n	80062b4 <_printf_core+0x2fc>
 80062c0:	465b      	mov	r3, fp
 80062c2:	9a08      	ldr	r2, [sp, #32]
 80062c4:	f7fa fb54 	bl	8000970 <__aeabi_uldivmod>
 80062c8:	9b0b      	ldr	r3, [sp, #44]	@ 0x2c
 80062ca:	5c9b      	ldrb	r3, [r3, r2]
 80062cc:	9a0a      	ldr	r2, [sp, #40]	@ 0x28
 80062ce:	1e52      	subs	r2, r2, #1
 80062d0:	920a      	str	r2, [sp, #40]	@ 0x28
 80062d2:	7013      	strb	r3, [r2, #0]
 80062d4:	ea50 0201 	orrs.w	r2, r0, r1
 80062d8:	d1f2      	bne.n	80062c0 <_printf_core+0x308>
 80062da:	980a      	ldr	r0, [sp, #40]	@ 0x28
 80062dc:	ebad 0000 	sub.w	r0, sp, r0
 80062e0:	f100 0b20 	add.w	fp, r0, #32
 80062e4:	0760      	lsls	r0, r4, #29
 80062e6:	d502      	bpl.n	80062ee <_printf_core+0x336>
 80062e8:	f424 3480 	bic.w	r4, r4, #65536	@ 0x10000
 80062ec:	e001      	b.n	80062f2 <_printf_core+0x33a>
 80062ee:	f04f 0901 	mov.w	r9, #1
 80062f2:	45d9      	cmp	r9, fp
 80062f4:	dd02      	ble.n	80062fc <_printf_core+0x344>
 80062f6:	eba9 000b 	sub.w	r0, r9, fp
 80062fa:	e000      	b.n	80062fe <_printf_core+0x346>
 80062fc:	2000      	movs	r0, #0
 80062fe:	eb00 010b 	add.w	r1, r0, fp
 8006302:	4441      	add	r1, r8
 8006304:	9008      	str	r0, [sp, #32]
 8006306:	ebaa 0a01 	sub.w	sl, sl, r1
 800630a:	03e0      	lsls	r0, r4, #15
 800630c:	d406      	bmi.n	800631c <_printf_core+0x364>
 800630e:	e9dd 230f 	ldrd	r2, r3, [sp, #60]	@ 0x3c
 8006312:	4621      	mov	r1, r4
 8006314:	4650      	mov	r0, sl
 8006316:	f000 f863 	bl	80063e0 <_printf_pre_padding>
 800631a:	4406      	add	r6, r0
 800631c:	f04f 0900 	mov.w	r9, #0
 8006320:	e008      	b.n	8006334 <_printf_core+0x37c>
 8006322:	a909      	add	r1, sp, #36	@ 0x24
 8006324:	f811 0009 	ldrb.w	r0, [r1, r9]
 8006328:	e9dd 120f 	ldrd	r1, r2, [sp, #60]	@ 0x3c
 800632c:	4790      	blx	r2
 800632e:	f109 0901 	add.w	r9, r9, #1
 8006332:	1c76      	adds	r6, r6, #1
 8006334:	45c1      	cmp	r9, r8
 8006336:	dbf4      	blt.n	8006322 <_printf_core+0x36a>
 8006338:	03e0      	lsls	r0, r4, #15
 800633a:	d50c      	bpl.n	8006356 <_printf_core+0x39e>
 800633c:	e9dd 230f 	ldrd	r2, r3, [sp, #60]	@ 0x3c
 8006340:	4621      	mov	r1, r4
 8006342:	4650      	mov	r0, sl
 8006344:	f000 f84c 	bl	80063e0 <_printf_pre_padding>
 8006348:	4406      	add	r6, r0
 800634a:	e004      	b.n	8006356 <_printf_core+0x39e>
 800634c:	e9dd 120f 	ldrd	r1, r2, [sp, #60]	@ 0x3c
 8006350:	2030      	movs	r0, #48	@ 0x30
 8006352:	4790      	blx	r2
 8006354:	1c76      	adds	r6, r6, #1
 8006356:	9908      	ldr	r1, [sp, #32]
 8006358:	1e48      	subs	r0, r1, #1
 800635a:	9008      	str	r0, [sp, #32]
 800635c:	2900      	cmp	r1, #0
 800635e:	dcf5      	bgt.n	800634c <_printf_core+0x394>
 8006360:	e008      	b.n	8006374 <_printf_core+0x3bc>
 8006362:	980a      	ldr	r0, [sp, #40]	@ 0x28
 8006364:	990a      	ldr	r1, [sp, #40]	@ 0x28
 8006366:	7800      	ldrb	r0, [r0, #0]
 8006368:	1c49      	adds	r1, r1, #1
 800636a:	910a      	str	r1, [sp, #40]	@ 0x28
 800636c:	e9dd 120f 	ldrd	r1, r2, [sp, #60]	@ 0x3c
 8006370:	4790      	blx	r2
 8006372:	1c76      	adds	r6, r6, #1
 8006374:	f1bb 0100 	subs.w	r1, fp, #0
 8006378:	f1ab 0b01 	sub.w	fp, fp, #1
 800637c:	dcf1      	bgt.n	8006362 <_printf_core+0x3aa>
 800637e:	4621      	mov	r1, r4
 8006380:	4650      	mov	r0, sl
 8006382:	e9dd 230f 	ldrd	r2, r3, [sp, #60]	@ 0x3c
 8006386:	f000 f819 	bl	80063bc <_printf_post_padding>
 800638a:	4406      	add	r6, r0
 800638c:	1c6d      	adds	r5, r5, #1
 800638e:	e621      	b.n	8005fd4 <_printf_core+0x1c>
 8006390:	00012809 	.word	0x00012809
 8006394:	33323130 	.word	0x33323130
 8006398:	37363534 	.word	0x37363534
 800639c:	62613938 	.word	0x62613938
 80063a0:	66656463 	.word	0x66656463
 80063a4:	00000000 	.word	0x00000000
 80063a8:	33323130 	.word	0x33323130
 80063ac:	37363534 	.word	0x37363534
 80063b0:	42413938 	.word	0x42413938
 80063b4:	46454443 	.word	0x46454443
 80063b8:	00000000 	.word	0x00000000

080063bc <_printf_post_padding>:
 80063bc:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 80063c0:	4604      	mov	r4, r0
 80063c2:	2500      	movs	r5, #0
 80063c4:	461e      	mov	r6, r3
 80063c6:	4617      	mov	r7, r2
 80063c8:	0488      	lsls	r0, r1, #18
 80063ca:	d404      	bmi.n	80063d6 <_printf_post_padding+0x1a>
 80063cc:	e005      	b.n	80063da <_printf_post_padding+0x1e>
 80063ce:	4639      	mov	r1, r7
 80063d0:	2020      	movs	r0, #32
 80063d2:	47b0      	blx	r6
 80063d4:	1c6d      	adds	r5, r5, #1
 80063d6:	1e64      	subs	r4, r4, #1
 80063d8:	d5f9      	bpl.n	80063ce <_printf_post_padding+0x12>
 80063da:	4628      	mov	r0, r5
 80063dc:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}

080063e0 <_printf_pre_padding>:
 80063e0:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 80063e4:	4604      	mov	r4, r0
 80063e6:	2500      	movs	r5, #0
 80063e8:	461e      	mov	r6, r3
 80063ea:	4690      	mov	r8, r2
 80063ec:	03c8      	lsls	r0, r1, #15
 80063ee:	d501      	bpl.n	80063f4 <_printf_pre_padding+0x14>
 80063f0:	2730      	movs	r7, #48	@ 0x30
 80063f2:	e000      	b.n	80063f6 <_printf_pre_padding+0x16>
 80063f4:	2720      	movs	r7, #32
 80063f6:	0488      	lsls	r0, r1, #18
 80063f8:	d504      	bpl.n	8006404 <_printf_pre_padding+0x24>
 80063fa:	e005      	b.n	8006408 <_printf_pre_padding+0x28>
 80063fc:	4641      	mov	r1, r8
 80063fe:	4638      	mov	r0, r7
 8006400:	47b0      	blx	r6
 8006402:	1c6d      	adds	r5, r5, #1
 8006404:	1e64      	subs	r4, r4, #1
 8006406:	d5f9      	bpl.n	80063fc <_printf_pre_padding+0x1c>
 8006408:	4628      	mov	r0, r5
 800640a:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
	...

08006410 <back_trace>:
 8006410:	b57f      	push	{r0, r1, r2, r3, r4, r5, r6, lr}
 8006412:	2000      	movs	r0, #0
 8006414:	9000      	str	r0, [sp, #0]
 8006416:	9001      	str	r0, [sp, #4]
 8006418:	9002      	str	r0, [sp, #8]
 800641a:	9003      	str	r0, [sp, #12]
 800641c:	4678      	mov	r0, pc
 800641e:	9002      	str	r0, [sp, #8]
 8006420:	9807      	ldr	r0, [sp, #28]
 8006422:	9001      	str	r0, [sp, #4]
 8006424:	4668      	mov	r0, sp
 8006426:	9000      	str	r0, [sp, #0]
 8006428:	e00e      	b.n	8006448 <back_trace+0x38>
 800642a:	9d02      	ldr	r5, [sp, #8]
 800642c:	4668      	mov	r0, sp
 800642e:	f000 faf5 	bl	8006a1c <unwind_frame>
 8006432:	4604      	mov	r4, r0
 8006434:	2c00      	cmp	r4, #0
 8006436:	da00      	bge.n	800643a <back_trace+0x2a>
 8006438:	e007      	b.n	800644a <back_trace+0x3a>
 800643a:	9802      	ldr	r0, [sp, #8]
 800643c:	1e42      	subs	r2, r0, #1
 800643e:	1e69      	subs	r1, r5, #1
 8006440:	a003      	add	r0, pc, #12	@ (adr r0, 8006450 <back_trace+0x40>)
 8006442:	f7ff fd7d 	bl	8005f40 <__0printf$8>
 8006446:	bf00      	nop
 8006448:	e7ef      	b.n	800642a <back_trace+0x1a>
 800644a:	bf00      	nop
 800644c:	bd7f      	pop	{r0, r1, r2, r3, r4, r5, r6, pc}
 800644e:	0000      	.short	0x0000
 8006450:	70257830 	.word	0x70257830
 8006454:	6f726620 	.word	0x6f726620
 8006458:	7830206d 	.word	0x7830206d
 800645c:	000a7025 	.word	0x000a7025

08006460 <decode_prel31>:
 8006460:	4602      	mov	r2, r0
 8006462:	f342 031e 	sbfx	r3, r2, #0, #31
 8006466:	18c8      	adds	r0, r1, r3
 8006468:	4770      	bx	lr
	...

0800646c <fputc>:
 800646c:	b538      	push	{r3, r4, r5, lr}
 800646e:	4604      	mov	r4, r0
 8006470:	460d      	mov	r5, r1
 8006472:	b2e0      	uxtb	r0, r4
 8006474:	9000      	str	r0, [sp, #0]
 8006476:	230a      	movs	r3, #10
 8006478:	2201      	movs	r2, #1
 800647a:	4669      	mov	r1, sp
 800647c:	4802      	ldr	r0, [pc, #8]	@ (8006488 <fputc+0x1c>)
 800647e:	f7ff f835 	bl	80054ec <HAL_UART_Transmit>
 8006482:	4620      	mov	r0, r4
 8006484:	bd38      	pop	{r3, r4, r5, pc}
 8006486:	0000      	.short	0x0000
 8006488:	20000028 	.word	0x20000028

0800648c <free>:
 800648c:	b510      	push	{r4, lr}
 800648e:	2800      	cmp	r0, #0
 8006490:	d021      	beq.n	80064d6 <free+0x4a>
 8006492:	4b11      	ldr	r3, [pc, #68]	@ (80064d8 <free+0x4c>)
 8006494:	2200      	movs	r2, #0
 8006496:	1f00      	subs	r0, r0, #4
 8006498:	6819      	ldr	r1, [r3, #0]
 800649a:	e003      	b.n	80064a4 <free+0x18>
 800649c:	4281      	cmp	r1, r0
 800649e:	d803      	bhi.n	80064a8 <free+0x1c>
 80064a0:	460a      	mov	r2, r1
 80064a2:	6849      	ldr	r1, [r1, #4]
 80064a4:	2900      	cmp	r1, #0
 80064a6:	d1f9      	bne.n	800649c <free+0x10>
 80064a8:	b152      	cbz	r2, 80064c0 <free+0x34>
 80064aa:	6813      	ldr	r3, [r2, #0]
 80064ac:	1a84      	subs	r4, r0, r2
 80064ae:	429c      	cmp	r4, r3
 80064b0:	d104      	bne.n	80064bc <free+0x30>
 80064b2:	6800      	ldr	r0, [r0, #0]
 80064b4:	4418      	add	r0, r3
 80064b6:	6010      	str	r0, [r2, #0]
 80064b8:	4610      	mov	r0, r2
 80064ba:	e002      	b.n	80064c2 <free+0x36>
 80064bc:	6050      	str	r0, [r2, #4]
 80064be:	e000      	b.n	80064c2 <free+0x36>
 80064c0:	6018      	str	r0, [r3, #0]
 80064c2:	b139      	cbz	r1, 80064d4 <free+0x48>
 80064c4:	6802      	ldr	r2, [r0, #0]
 80064c6:	1a0b      	subs	r3, r1, r0
 80064c8:	4293      	cmp	r3, r2
 80064ca:	d103      	bne.n	80064d4 <free+0x48>
 80064cc:	680b      	ldr	r3, [r1, #0]
 80064ce:	441a      	add	r2, r3
 80064d0:	6002      	str	r2, [r0, #0]
 80064d2:	6849      	ldr	r1, [r1, #4]
 80064d4:	6041      	str	r1, [r0, #4]
 80064d6:	bd10      	pop	{r4, pc}
 80064d8:	20000020 	.word	0x20000020

080064dc <main>:
 80064dc:	b508      	push	{r3, lr}
 80064de:	f7fc fe7d 	bl	80031dc <HAL_Init>
 80064e2:	f7ff f932 	bl	800574a <SystemClock_Config>
 80064e6:	f7ff f8c7 	bl	8005678 <MX_GPIO_Init>
 80064ea:	f7ff f8f1 	bl	80056d0 <MX_USART1_UART_Init>
 80064ee:	f000 f865 	bl	80065bc <show_unwind_info>
 80064f2:	2000      	movs	r0, #0
 80064f4:	4603      	mov	r3, r0
 80064f6:	4602      	mov	r2, r0
 80064f8:	4601      	mov	r1, r0
 80064fa:	9000      	str	r0, [sp, #0]
 80064fc:	f000 f8c4 	bl	8006688 <test_a>
 8006500:	bf00      	nop
 8006502:	e7fe      	b.n	8006502 <main+0x26>

08006504 <malloc>:
 8006504:	b5f0      	push	{r4, r5, r6, r7, lr}
 8006506:	300b      	adds	r0, #11
 8006508:	4d15      	ldr	r5, [pc, #84]	@ (8006560 <malloc+0x5c>)
 800650a:	f020 0107 	bic.w	r1, r0, #7
 800650e:	2400      	movs	r4, #0
 8006510:	4a14      	ldr	r2, [pc, #80]	@ (8006564 <malloc+0x60>)
 8006512:	e00f      	b.n	8006534 <malloc+0x30>
 8006514:	6803      	ldr	r3, [r0, #0]
 8006516:	428b      	cmp	r3, r1
 8006518:	d30b      	bcc.n	8006532 <malloc+0x2e>
 800651a:	428b      	cmp	r3, r1
 800651c:	d905      	bls.n	800652a <malloc+0x26>
 800651e:	1a5e      	subs	r6, r3, r1
 8006520:	1843      	adds	r3, r0, r1
 8006522:	6847      	ldr	r7, [r0, #4]
 8006524:	e9c3 6700 	strd	r6, r7, [r3]
 8006528:	e000      	b.n	800652c <malloc+0x28>
 800652a:	6843      	ldr	r3, [r0, #4]
 800652c:	6013      	str	r3, [r2, #0]
 800652e:	c002      	stmia	r0!, {r1}
 8006530:	e004      	b.n	800653c <malloc+0x38>
 8006532:	1d02      	adds	r2, r0, #4
 8006534:	6810      	ldr	r0, [r2, #0]
 8006536:	2800      	cmp	r0, #0
 8006538:	d1ec      	bne.n	8006514 <malloc+0x10>
 800653a:	4620      	mov	r0, r4
 800653c:	2800      	cmp	r0, #0
 800653e:	d102      	bne.n	8006546 <malloc+0x42>
 8006540:	6828      	ldr	r0, [r5, #0]
 8006542:	b108      	cbz	r0, 8006548 <malloc+0x44>
 8006544:	2000      	movs	r0, #0
 8006546:	bdf0      	pop	{r4, r5, r6, r7, pc}
 8006548:	4a06      	ldr	r2, [pc, #24]	@ (8006564 <malloc+0x60>)
 800654a:	4807      	ldr	r0, [pc, #28]	@ (8006568 <malloc+0x64>)
 800654c:	6010      	str	r0, [r2, #0]
 800654e:	4a07      	ldr	r2, [pc, #28]	@ (800656c <malloc+0x68>)
 8006550:	1a12      	subs	r2, r2, r0
 8006552:	f022 0207 	bic.w	r2, r2, #7
 8006556:	e9c0 2400 	strd	r2, r4, [r0]
 800655a:	2001      	movs	r0, #1
 800655c:	6028      	str	r0, [r5, #0]
 800655e:	e7d7      	b.n	8006510 <malloc+0xc>
 8006560:	20000024 	.word	0x20000024
 8006564:	20000020 	.word	0x20000020
 8006568:	20000094 	.word	0x20000094
 800656c:	20000290 	.word	0x20000290

08006570 <search_index>:
 8006570:	b5f0      	push	{r4, r5, r6, r7, lr}
 8006572:	4604      	mov	r4, r0
 8006574:	4615      	mov	r5, r2
 8006576:	428c      	cmp	r4, r1
 8006578:	d201      	bcs.n	800657e <search_index+0xe>
 800657a:	462b      	mov	r3, r5
 800657c:	e000      	b.n	8006580 <search_index+0x10>
 800657e:	4629      	mov	r1, r5
 8006580:	1a60      	subs	r0, r4, r1
 8006582:	f020 4200 	bic.w	r2, r0, #2147483648	@ 0x80000000
 8006586:	e00e      	b.n	80065a6 <search_index+0x36>
 8006588:	1a5e      	subs	r6, r3, r1
 800658a:	1136      	asrs	r6, r6, #4
 800658c:	eb01 00c6 	add.w	r0, r1, r6, lsl #3
 8006590:	1a46      	subs	r6, r0, r1
 8006592:	1b96      	subs	r6, r2, r6
 8006594:	6807      	ldr	r7, [r0, #0]
 8006596:	42be      	cmp	r6, r7
 8006598:	d201      	bcs.n	800659e <search_index+0x2e>
 800659a:	4603      	mov	r3, r0
 800659c:	e002      	b.n	80065a4 <search_index+0x34>
 800659e:	1a46      	subs	r6, r0, r1
 80065a0:	1b92      	subs	r2, r2, r6
 80065a2:	4601      	mov	r1, r0
 80065a4:	bf00      	nop
 80065a6:	f1a3 0008 	sub.w	r0, r3, #8
 80065aa:	4288      	cmp	r0, r1
 80065ac:	d8ec      	bhi.n	8006588 <search_index+0x18>
 80065ae:	6808      	ldr	r0, [r1, #0]
 80065b0:	4290      	cmp	r0, r2
 80065b2:	d801      	bhi.n	80065b8 <search_index+0x48>
 80065b4:	4608      	mov	r0, r1
 80065b6:	bdf0      	pop	{r4, r5, r6, r7, pc}
 80065b8:	2000      	movs	r0, #0
 80065ba:	e7fc      	b.n	80065b6 <search_index+0x46>

080065bc <show_unwind_info>:
 80065bc:	e92d 47f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, lr}
 80065c0:	4c13      	ldr	r4, [pc, #76]	@ (8006610 <show_unwind_info+0x54>)
 80065c2:	4e14      	ldr	r6, [pc, #80]	@ (8006614 <show_unwind_info+0x58>)
 80065c4:	f8df 9050 	ldr.w	r9, [pc, #80]	@ 8006618 <show_unwind_info+0x5c>
 80065c8:	08f7      	lsrs	r7, r6, #3
 80065ca:	464b      	mov	r3, r9
 80065cc:	4632      	mov	r2, r6
 80065ce:	4621      	mov	r1, r4
 80065d0:	a012      	add	r0, pc, #72	@ (adr r0, 800661c <show_unwind_info+0x60>)
 80065d2:	f7ff fcb5 	bl	8005f40 <__0printf$8>
 80065d6:	4639      	mov	r1, r7
 80065d8:	a01b      	add	r0, pc, #108	@ (adr r0, 8006648 <show_unwind_info+0x8c>)
 80065da:	f7ff fcb1 	bl	8005f40 <__0printf$8>
 80065de:	f04f 0800 	mov.w	r8, #0
 80065e2:	e011      	b.n	8006608 <show_unwind_info+0x4c>
 80065e4:	f04f 0a00 	mov.w	sl, #0
 80065e8:	4625      	mov	r5, r4
 80065ea:	462c      	mov	r4, r5
 80065ec:	4629      	mov	r1, r5
 80065ee:	6828      	ldr	r0, [r5, #0]
 80065f0:	f7ff ff36 	bl	8006460 <decode_prel31>
 80065f4:	4682      	mov	sl, r0
 80065f6:	4652      	mov	r2, sl
 80065f8:	a017      	add	r0, pc, #92	@ (adr r0, 8006658 <show_unwind_info+0x9c>)
 80065fa:	e9d5 1300 	ldrd	r1, r3, [r5]
 80065fe:	f7ff fc9f 	bl	8005f40 <__0printf$8>
 8006602:	3408      	adds	r4, #8
 8006604:	f108 0801 	add.w	r8, r8, #1
 8006608:	45b8      	cmp	r8, r7
 800660a:	d3eb      	bcc.n	80065e4 <show_unwind_info+0x28>
 800660c:	e8bd 87f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, pc}
 8006610:	08006d28 	.word	0x08006d28
 8006614:	00000498 	.word	0x00000498
 8006618:	080071c0 	.word	0x080071c0
 800661c:	65736162 	.word	0x65736162
 8006620:	6464615f 	.word	0x6464615f
 8006624:	78303d72 	.word	0x78303d72
 8006628:	202c7825 	.word	0x202c7825
 800662c:	676e656c 	.word	0x676e656c
 8006630:	303d6874 	.word	0x303d6874
 8006634:	2c782578 	.word	0x2c782578
 8006638:	646e6520 	.word	0x646e6520
 800663c:	6464615f 	.word	0x6464615f
 8006640:	78303d72 	.word	0x78303d72
 8006644:	000a7825 	.word	0x000a7825
 8006648:	72746e65 	.word	0x72746e65
 800664c:	756e2079 	.word	0x756e2079
 8006650:	64253d6d 	.word	0x64253d6d
 8006654:	0000000a 	.word	0x0000000a
 8006658:	2d786469 	.word	0x2d786469
 800665c:	6464613e 	.word	0x6464613e
 8006660:	666f5f72 	.word	0x666f5f72
 8006664:	74657366 	.word	0x74657366
 8006668:	2578303d 	.word	0x2578303d
 800666c:	70202c78 	.word	0x70202c78
 8006670:	78303d63 	.word	0x78303d63
 8006674:	202c7825 	.word	0x202c7825
 8006678:	2d786469 	.word	0x2d786469
 800667c:	736e693e 	.word	0x736e693e
 8006680:	2578303d 	.word	0x2578303d
 8006684:	00000a78 	.word	0x00000a78

08006688 <test_a>:
 8006688:	e92d 47f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, lr}
 800668c:	4606      	mov	r6, r0
 800668e:	460f      	mov	r7, r1
 8006690:	4690      	mov	r8, r2
 8006692:	4699      	mov	r9, r3
 8006694:	9d08      	ldr	r5, [sp, #32]
 8006696:	f64f 7411 	movw	r4, #65297	@ 0xff11
 800669a:	f44f 403b 	mov.w	r0, #47872	@ 0xbb00
 800669e:	f000 f803 	bl	80066a8 <test_b>
 80066a2:	4620      	mov	r0, r4
 80066a4:	e8bd 87f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, r9, sl, pc}

080066a8 <test_b>:
 80066a8:	b570      	push	{r4, r5, r6, lr}
 80066aa:	4605      	mov	r5, r0
 80066ac:	f64f 7422 	movw	r4, #65314	@ 0xff22
 80066b0:	f44f 404c 	mov.w	r0, #52224	@ 0xcc00
 80066b4:	f000 f802 	bl	80066bc <test_c>
 80066b8:	4620      	mov	r0, r4
 80066ba:	bd70      	pop	{r4, r5, r6, pc}

080066bc <test_c>:
 80066bc:	b570      	push	{r4, r5, r6, lr}
 80066be:	4606      	mov	r6, r0
 80066c0:	f64f 7433 	movw	r4, #65331	@ 0xff33
 80066c4:	4625      	mov	r5, r4
 80066c6:	f7ff fea3 	bl	8006410 <back_trace>
 80066ca:	1960      	adds	r0, r4, r5
 80066cc:	bd70      	pop	{r4, r5, r6, pc}

080066ce <unwind_decode_uleb128>:
 80066ce:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 80066d2:	4607      	mov	r7, r0
 80066d4:	2500      	movs	r5, #0
 80066d6:	2600      	movs	r6, #0
 80066d8:	bf00      	nop
 80066da:	4638      	mov	r0, r7
 80066dc:	f000 fa7a 	bl	8006bd4 <unwind_get_byte>
 80066e0:	4604      	mov	r4, r0
 80066e2:	f004 007f 	and.w	r0, r4, #127	@ 0x7f
 80066e6:	ebc5 01c5 	rsb	r1, r5, r5, lsl #3
 80066ea:	4088      	lsls	r0, r1
 80066ec:	4306      	orrs	r6, r0
 80066ee:	1c6d      	adds	r5, r5, #1
 80066f0:	f004 0080 	and.w	r0, r4, #128	@ 0x80
 80066f4:	b108      	cbz	r0, 80066fa <unwind_decode_uleb128+0x2c>
 80066f6:	2d04      	cmp	r5, #4
 80066f8:	d1ef      	bne.n	80066da <unwind_decode_uleb128+0xc>
 80066fa:	4630      	mov	r0, r6
 80066fc:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}

08006700 <unwind_exec_insn>:
 8006700:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8006702:	4605      	mov	r5, r0
 8006704:	4628      	mov	r0, r5
 8006706:	f000 fa65 	bl	8006bd4 <unwind_get_byte>
 800670a:	4604      	mov	r4, r0
 800670c:	2600      	movs	r6, #0
 800670e:	4622      	mov	r2, r4
 8006710:	494a      	ldr	r1, [pc, #296]	@ (800683c <unwind_exec_insn+0x13c>)
 8006712:	a04b      	add	r0, pc, #300	@ (adr r0, 8006840 <unwind_exec_insn+0x140>)
 8006714:	f7ff fc14 	bl	8005f40 <__0printf$8>
 8006718:	f004 00c0 	and.w	r0, r4, #192	@ 0xc0
 800671c:	b940      	cbnz	r0, 8006730 <unwind_exec_insn+0x30>
 800671e:	f004 013f 	and.w	r1, r4, #63	@ 0x3f
 8006722:	2204      	movs	r2, #4
 8006724:	eb02 0181 	add.w	r1, r2, r1, lsl #2
 8006728:	6b68      	ldr	r0, [r5, #52]	@ 0x34
 800672a:	4408      	add	r0, r1
 800672c:	6368      	str	r0, [r5, #52]	@ 0x34
 800672e:	e079      	b.n	8006824 <unwind_exec_insn+0x124>
 8006730:	f004 00c0 	and.w	r0, r4, #192	@ 0xc0
 8006734:	2840      	cmp	r0, #64	@ 0x40
 8006736:	d108      	bne.n	800674a <unwind_exec_insn+0x4a>
 8006738:	f004 013f 	and.w	r1, r4, #63	@ 0x3f
 800673c:	2204      	movs	r2, #4
 800673e:	eb02 0181 	add.w	r1, r2, r1, lsl #2
 8006742:	6b68      	ldr	r0, [r5, #52]	@ 0x34
 8006744:	1a40      	subs	r0, r0, r1
 8006746:	6368      	str	r0, [r5, #52]	@ 0x34
 8006748:	e06c      	b.n	8006824 <unwind_exec_insn+0x124>
 800674a:	f004 00f0 	and.w	r0, r4, #240	@ 0xf0
 800674e:	2880      	cmp	r0, #128	@ 0x80
 8006750:	d116      	bne.n	8006780 <unwind_exec_insn+0x80>
 8006752:	4628      	mov	r0, r5
 8006754:	f000 fa3e 	bl	8006bd4 <unwind_get_byte>
 8006758:	ea40 2404 	orr.w	r4, r0, r4, lsl #8
 800675c:	f3c4 070b 	ubfx	r7, r4, #0, #12
 8006760:	b937      	cbnz	r7, 8006770 <unwind_exec_insn+0x70>
 8006762:	4621      	mov	r1, r4
 8006764:	a03b      	add	r0, pc, #236	@ (adr r0, 8006854 <unwind_exec_insn+0x154>)
 8006766:	f7ff fbeb 	bl	8005f40 <__0printf$8>
 800676a:	f06f 0008 	mvn.w	r0, #8
 800676e:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 8006770:	4639      	mov	r1, r7
 8006772:	4628      	mov	r0, r5
 8006774:	f000 f8ff 	bl	8006976 <unwind_exec_pop_subset_r4_to_r13>
 8006778:	4606      	mov	r6, r0
 800677a:	b106      	cbz	r6, 800677e <unwind_exec_insn+0x7e>
 800677c:	e05b      	b.n	8006836 <unwind_exec_insn+0x136>
 800677e:	e051      	b.n	8006824 <unwind_exec_insn+0x124>
 8006780:	f004 00f0 	and.w	r0, r4, #240	@ 0xf0
 8006784:	2890      	cmp	r0, #144	@ 0x90
 8006786:	d109      	bne.n	800679c <unwind_exec_insn+0x9c>
 8006788:	f004 000d 	and.w	r0, r4, #13
 800678c:	280d      	cmp	r0, #13
 800678e:	d005      	beq.n	800679c <unwind_exec_insn+0x9c>
 8006790:	f004 000f 	and.w	r0, r4, #15
 8006794:	f855 0020 	ldr.w	r0, [r5, r0, lsl #2]
 8006798:	6368      	str	r0, [r5, #52]	@ 0x34
 800679a:	e043      	b.n	8006824 <unwind_exec_insn+0x124>
 800679c:	f004 00f0 	and.w	r0, r4, #240	@ 0xf0
 80067a0:	28a0      	cmp	r0, #160	@ 0xa0
 80067a2:	d107      	bne.n	80067b4 <unwind_exec_insn+0xb4>
 80067a4:	4621      	mov	r1, r4
 80067a6:	4628      	mov	r0, r5
 80067a8:	f000 f8a4 	bl	80068f4 <unwind_exec_pop_r4_to_rN>
 80067ac:	4606      	mov	r6, r0
 80067ae:	2e00      	cmp	r6, #0
 80067b0:	d038      	beq.n	8006824 <unwind_exec_insn+0x124>
 80067b2:	e040      	b.n	8006836 <unwind_exec_insn+0x136>
 80067b4:	2cb0      	cmp	r4, #176	@ 0xb0
 80067b6:	d106      	bne.n	80067c6 <unwind_exec_insn+0xc6>
 80067b8:	6be8      	ldr	r0, [r5, #60]	@ 0x3c
 80067ba:	b908      	cbnz	r0, 80067c0 <unwind_exec_insn+0xc0>
 80067bc:	6ba8      	ldr	r0, [r5, #56]	@ 0x38
 80067be:	63e8      	str	r0, [r5, #60]	@ 0x3c
 80067c0:	2000      	movs	r0, #0
 80067c2:	6528      	str	r0, [r5, #80]	@ 0x50
 80067c4:	e02e      	b.n	8006824 <unwind_exec_insn+0x124>
 80067c6:	2cb1      	cmp	r4, #177	@ 0xb1
 80067c8:	d117      	bne.n	80067fa <unwind_exec_insn+0xfa>
 80067ca:	4628      	mov	r0, r5
 80067cc:	f000 fa02 	bl	8006bd4 <unwind_get_byte>
 80067d0:	4607      	mov	r7, r0
 80067d2:	b117      	cbz	r7, 80067da <unwind_exec_insn+0xda>
 80067d4:	f007 00f0 	and.w	r0, r7, #240	@ 0xf0
 80067d8:	b138      	cbz	r0, 80067ea <unwind_exec_insn+0xea>
 80067da:	ea47 2104 	orr.w	r1, r7, r4, lsl #8
 80067de:	a029      	add	r0, pc, #164	@ (adr r0, 8006884 <unwind_exec_insn+0x184>)
 80067e0:	f7ff fbae 	bl	8005f40 <__0printf$8>
 80067e4:	f06f 0008 	mvn.w	r0, #8
 80067e8:	e7c1      	b.n	800676e <unwind_exec_insn+0x6e>
 80067ea:	4639      	mov	r1, r7
 80067ec:	4628      	mov	r0, r5
 80067ee:	f000 f8a7 	bl	8006940 <unwind_exec_pop_subset_r0_to_r3>
 80067f2:	4606      	mov	r6, r0
 80067f4:	b106      	cbz	r6, 80067f8 <unwind_exec_insn+0xf8>
 80067f6:	e01e      	b.n	8006836 <unwind_exec_insn+0x136>
 80067f8:	e014      	b.n	8006824 <unwind_exec_insn+0x124>
 80067fa:	2cb2      	cmp	r4, #178	@ 0xb2
 80067fc:	d10b      	bne.n	8006816 <unwind_exec_insn+0x116>
 80067fe:	4628      	mov	r0, r5
 8006800:	f7ff ff65 	bl	80066ce <unwind_decode_uleb128>
 8006804:	4607      	mov	r7, r0
 8006806:	f44f 7101 	mov.w	r1, #516	@ 0x204
 800680a:	eb01 0187 	add.w	r1, r1, r7, lsl #2
 800680e:	6b68      	ldr	r0, [r5, #52]	@ 0x34
 8006810:	4408      	add	r0, r1
 8006812:	6368      	str	r0, [r5, #52]	@ 0x34
 8006814:	e006      	b.n	8006824 <unwind_exec_insn+0x124>
 8006816:	4621      	mov	r1, r4
 8006818:	a022      	add	r0, pc, #136	@ (adr r0, 80068a4 <unwind_exec_insn+0x1a4>)
 800681a:	f7ff fb91 	bl	8005f40 <__0printf$8>
 800681e:	f06f 0008 	mvn.w	r0, #8
 8006822:	e7a4      	b.n	800676e <unwind_exec_insn+0x6e>
 8006824:	6be8      	ldr	r0, [r5, #60]	@ 0x3c
 8006826:	9000      	str	r0, [sp, #0]
 8006828:	4904      	ldr	r1, [pc, #16]	@ (800683c <unwind_exec_insn+0x13c>)
 800682a:	a028      	add	r0, pc, #160	@ (adr r0, 80068cc <unwind_exec_insn+0x1cc>)
 800682c:	e9d5 230d 	ldrd	r2, r3, [r5, #52]	@ 0x34
 8006830:	f7ff fb86 	bl	8005f40 <__0printf$8>
 8006834:	bf00      	nop
 8006836:	4630      	mov	r0, r6
 8006838:	e799      	b.n	800676e <unwind_exec_insn+0x6e>
 800683a:	0000      	.short	0x0000
 800683c:	08006c74 	.word	0x08006c74
 8006840:	203a7325 	.word	0x203a7325
 8006844:	6e736e69 	.word	0x6e736e69
 8006848:	25203d20 	.word	0x25203d20
 800684c:	786c3830 	.word	0x786c3830
 8006850:	0000000a 	.word	0x0000000a
 8006854:	69776e75 	.word	0x69776e75
 8006858:	203a646e 	.word	0x203a646e
 800685c:	66655227 	.word	0x66655227
 8006860:	20657375 	.word	0x20657375
 8006864:	75206f74 	.word	0x75206f74
 8006868:	6e69776e 	.word	0x6e69776e
 800686c:	69202764 	.word	0x69202764
 8006870:	7274736e 	.word	0x7274736e
 8006874:	69746375 	.word	0x69746375
 8006878:	25206e6f 	.word	0x25206e6f
 800687c:	786c3430 	.word	0x786c3430
 8006880:	0000000a 	.word	0x0000000a
 8006884:	69776e75 	.word	0x69776e75
 8006888:	203a646e 	.word	0x203a646e
 800688c:	72617053 	.word	0x72617053
 8006890:	6e652065 	.word	0x6e652065
 8006894:	69646f63 	.word	0x69646f63
 8006898:	2520676e 	.word	0x2520676e
 800689c:	786c3430 	.word	0x786c3430
 80068a0:	0000000a 	.word	0x0000000a
 80068a4:	69776e75 	.word	0x69776e75
 80068a8:	203a646e 	.word	0x203a646e
 80068ac:	61686e55 	.word	0x61686e55
 80068b0:	656c646e 	.word	0x656c646e
 80068b4:	6e692064 	.word	0x6e692064
 80068b8:	75727473 	.word	0x75727473
 80068bc:	6f697463 	.word	0x6f697463
 80068c0:	3025206e 	.word	0x3025206e
 80068c4:	0a786c32 	.word	0x0a786c32
 80068c8:	00000000 	.word	0x00000000
 80068cc:	203a7325 	.word	0x203a7325
 80068d0:	3d207073 	.word	0x3d207073
 80068d4:	38302520 	.word	0x38302520
 80068d8:	6c20786c 	.word	0x6c20786c
 80068dc:	203d2072 	.word	0x203d2072
 80068e0:	6c383025 	.word	0x6c383025
 80068e4:	63702078 	.word	0x63702078
 80068e8:	25203d20 	.word	0x25203d20
 80068ec:	786c3830 	.word	0x786c3830
 80068f0:	0000000a 	.word	0x0000000a

080068f4 <unwind_exec_pop_r4_to_rN>:
 80068f4:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 80068f6:	4604      	mov	r4, r0
 80068f8:	460d      	mov	r5, r1
 80068fa:	6b60      	ldr	r0, [r4, #52]	@ 0x34
 80068fc:	9000      	str	r0, [sp, #0]
 80068fe:	2604      	movs	r6, #4
 8006900:	e009      	b.n	8006916 <unwind_exec_pop_r4_to_rN+0x22>
 8006902:	4632      	mov	r2, r6
 8006904:	4669      	mov	r1, sp
 8006906:	4620      	mov	r0, r4
 8006908:	f000 f996 	bl	8006c38 <unwind_pop_register>
 800690c:	b110      	cbz	r0, 8006914 <unwind_exec_pop_r4_to_rN+0x20>
 800690e:	f06f 0008 	mvn.w	r0, #8
 8006912:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 8006914:	1c76      	adds	r6, r6, #1
 8006916:	f005 0007 	and.w	r0, r5, #7
 800691a:	1d00      	adds	r0, r0, #4
 800691c:	42b0      	cmp	r0, r6
 800691e:	d2f0      	bcs.n	8006902 <unwind_exec_pop_r4_to_rN+0xe>
 8006920:	f005 0008 	and.w	r0, r5, #8
 8006924:	b140      	cbz	r0, 8006938 <unwind_exec_pop_r4_to_rN+0x44>
 8006926:	220e      	movs	r2, #14
 8006928:	4669      	mov	r1, sp
 800692a:	4620      	mov	r0, r4
 800692c:	f000 f984 	bl	8006c38 <unwind_pop_register>
 8006930:	b110      	cbz	r0, 8006938 <unwind_exec_pop_r4_to_rN+0x44>
 8006932:	f06f 0008 	mvn.w	r0, #8
 8006936:	e7ec      	b.n	8006912 <unwind_exec_pop_r4_to_rN+0x1e>
 8006938:	9800      	ldr	r0, [sp, #0]
 800693a:	6360      	str	r0, [r4, #52]	@ 0x34
 800693c:	2000      	movs	r0, #0
 800693e:	e7e8      	b.n	8006912 <unwind_exec_pop_r4_to_rN+0x1e>

08006940 <unwind_exec_pop_subset_r0_to_r3>:
 8006940:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8006942:	4605      	mov	r5, r0
 8006944:	460c      	mov	r4, r1
 8006946:	6b68      	ldr	r0, [r5, #52]	@ 0x34
 8006948:	9000      	str	r0, [sp, #0]
 800694a:	2600      	movs	r6, #0
 800694c:	e00d      	b.n	800696a <unwind_exec_pop_subset_r0_to_r3+0x2a>
 800694e:	f004 0001 	and.w	r0, r4, #1
 8006952:	b140      	cbz	r0, 8006966 <unwind_exec_pop_subset_r0_to_r3+0x26>
 8006954:	4632      	mov	r2, r6
 8006956:	4669      	mov	r1, sp
 8006958:	4628      	mov	r0, r5
 800695a:	f000 f96d 	bl	8006c38 <unwind_pop_register>
 800695e:	b110      	cbz	r0, 8006966 <unwind_exec_pop_subset_r0_to_r3+0x26>
 8006960:	f06f 0008 	mvn.w	r0, #8
 8006964:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 8006966:	0864      	lsrs	r4, r4, #1
 8006968:	1c76      	adds	r6, r6, #1
 800696a:	2c00      	cmp	r4, #0
 800696c:	d1ef      	bne.n	800694e <unwind_exec_pop_subset_r0_to_r3+0xe>
 800696e:	9800      	ldr	r0, [sp, #0]
 8006970:	6368      	str	r0, [r5, #52]	@ 0x34
 8006972:	2000      	movs	r0, #0
 8006974:	e7f6      	b.n	8006964 <unwind_exec_pop_subset_r0_to_r3+0x24>

08006976 <unwind_exec_pop_subset_r4_to_r13>:
 8006976:	b5f8      	push	{r3, r4, r5, r6, r7, lr}
 8006978:	4605      	mov	r5, r0
 800697a:	460c      	mov	r4, r1
 800697c:	6b68      	ldr	r0, [r5, #52]	@ 0x34
 800697e:	9000      	str	r0, [sp, #0]
 8006980:	2604      	movs	r6, #4
 8006982:	f404 7700 	and.w	r7, r4, #512	@ 0x200
 8006986:	e00d      	b.n	80069a4 <unwind_exec_pop_subset_r4_to_r13+0x2e>
 8006988:	f004 0001 	and.w	r0, r4, #1
 800698c:	b140      	cbz	r0, 80069a0 <unwind_exec_pop_subset_r4_to_r13+0x2a>
 800698e:	4632      	mov	r2, r6
 8006990:	4669      	mov	r1, sp
 8006992:	4628      	mov	r0, r5
 8006994:	f000 f950 	bl	8006c38 <unwind_pop_register>
 8006998:	b110      	cbz	r0, 80069a0 <unwind_exec_pop_subset_r4_to_r13+0x2a>
 800699a:	f06f 0008 	mvn.w	r0, #8
 800699e:	bdf8      	pop	{r3, r4, r5, r6, r7, pc}
 80069a0:	0864      	lsrs	r4, r4, #1
 80069a2:	1c76      	adds	r6, r6, #1
 80069a4:	2c00      	cmp	r4, #0
 80069a6:	d1ef      	bne.n	8006988 <unwind_exec_pop_subset_r4_to_r13+0x12>
 80069a8:	b90f      	cbnz	r7, 80069ae <unwind_exec_pop_subset_r4_to_r13+0x38>
 80069aa:	9800      	ldr	r0, [sp, #0]
 80069ac:	6368      	str	r0, [r5, #52]	@ 0x34
 80069ae:	2000      	movs	r0, #0
 80069b0:	e7f5      	b.n	800699e <unwind_exec_pop_subset_r4_to_r13+0x28>
	...

080069b4 <unwind_find_idx>:
 80069b4:	b570      	push	{r4, r5, r6, lr}
 80069b6:	4604      	mov	r4, r0
 80069b8:	480b      	ldr	r0, [pc, #44]	@ (80069e8 <unwind_find_idx+0x34>)
 80069ba:	6800      	ldr	r0, [r0, #0]
 80069bc:	b938      	cbnz	r0, 80069ce <unwind_find_idx+0x1a>
 80069be:	480b      	ldr	r0, [pc, #44]	@ (80069ec <unwind_find_idx+0x38>)
 80069c0:	6801      	ldr	r1, [r0, #0]
 80069c2:	480b      	ldr	r0, [pc, #44]	@ (80069f0 <unwind_find_idx+0x3c>)
 80069c4:	6800      	ldr	r0, [r0, #0]
 80069c6:	f000 f815 	bl	80069f4 <unwind_find_origin>
 80069ca:	4907      	ldr	r1, [pc, #28]	@ (80069e8 <unwind_find_idx+0x34>)
 80069cc:	6008      	str	r0, [r1, #0]
 80069ce:	4807      	ldr	r0, [pc, #28]	@ (80069ec <unwind_find_idx+0x38>)
 80069d0:	6803      	ldr	r3, [r0, #0]
 80069d2:	4805      	ldr	r0, [pc, #20]	@ (80069e8 <unwind_find_idx+0x34>)
 80069d4:	6802      	ldr	r2, [r0, #0]
 80069d6:	4806      	ldr	r0, [pc, #24]	@ (80069f0 <unwind_find_idx+0x3c>)
 80069d8:	6801      	ldr	r1, [r0, #0]
 80069da:	4620      	mov	r0, r4
 80069dc:	f7ff fdc8 	bl	8006570 <search_index>
 80069e0:	4605      	mov	r5, r0
 80069e2:	4628      	mov	r0, r5
 80069e4:	bd70      	pop	{r4, r5, r6, pc}
 80069e6:	0000      	.short	0x0000
 80069e8:	20000008 	.word	0x20000008
 80069ec:	20000004 	.word	0x20000004
 80069f0:	20000000 	.word	0x20000000

080069f4 <unwind_find_origin>:
 80069f4:	4602      	mov	r2, r0
 80069f6:	e00c      	b.n	8006a12 <unwind_find_origin+0x1e>
 80069f8:	1a8b      	subs	r3, r1, r2
 80069fa:	111b      	asrs	r3, r3, #4
 80069fc:	eb02 00c3 	add.w	r0, r2, r3, lsl #3
 8006a00:	6803      	ldr	r3, [r0, #0]
 8006a02:	f1b3 4f80 	cmp.w	r3, #1073741824	@ 0x40000000
 8006a06:	d302      	bcc.n	8006a0e <unwind_find_origin+0x1a>
 8006a08:	f100 0208 	add.w	r2, r0, #8
 8006a0c:	e000      	b.n	8006a10 <unwind_find_origin+0x1c>
 8006a0e:	4601      	mov	r1, r0
 8006a10:	bf00      	nop
 8006a12:	428a      	cmp	r2, r1
 8006a14:	d3f0      	bcc.n	80069f8 <unwind_find_origin+0x4>
 8006a16:	4608      	mov	r0, r1
 8006a18:	4770      	bx	lr
	...

08006a1c <unwind_frame>:
 8006a1c:	e92d 41f0 	stmdb	sp!, {r4, r5, r6, r7, r8, lr}
 8006a20:	b096      	sub	sp, #88	@ 0x58
 8006a22:	4604      	mov	r4, r0
 8006a24:	2700      	movs	r7, #0
 8006a26:	a04f      	add	r0, pc, #316	@ (adr r0, 8006b64 <unwind_frame+0x148>)
 8006a28:	f7ff fa8a 	bl	8005f40 <__0printf$8>
 8006a2c:	f8d4 8000 	ldr.w	r8, [r4]
 8006a30:	68a0      	ldr	r0, [r4, #8]
 8006a32:	f7ff ffbf 	bl	80069b4 <unwind_find_idx>
 8006a36:	4605      	mov	r5, r0
 8006a38:	4629      	mov	r1, r5
 8006a3a:	6828      	ldr	r0, [r5, #0]
 8006a3c:	f7ff fd10 	bl	8006460 <decode_prel31>
 8006a40:	4607      	mov	r7, r0
 8006a42:	463a      	mov	r2, r7
 8006a44:	a048      	add	r0, pc, #288	@ (adr r0, 8006b68 <unwind_frame+0x14c>)
 8006a46:	e9d5 1300 	ldrd	r1, r3, [r5]
 8006a4a:	f7ff fa79 	bl	8005f40 <__0printf$8>
 8006a4e:	6820      	ldr	r0, [r4, #0]
 8006a50:	900d      	str	r0, [sp, #52]	@ 0x34
 8006a52:	6860      	ldr	r0, [r4, #4]
 8006a54:	900e      	str	r0, [sp, #56]	@ 0x38
 8006a56:	2000      	movs	r0, #0
 8006a58:	900f      	str	r0, [sp, #60]	@ 0x3c
 8006a5a:	6868      	ldr	r0, [r5, #4]
 8006a5c:	2801      	cmp	r0, #1
 8006a5e:	d104      	bne.n	8006a6a <unwind_frame+0x4e>
 8006a60:	f06f 0008 	mvn.w	r0, #8
 8006a64:	b016      	add	sp, #88	@ 0x58
 8006a66:	e8bd 81f0 	ldmia.w	sp!, {r4, r5, r6, r7, r8, pc}
 8006a6a:	682a      	ldr	r2, [r5, #0]
 8006a6c:	f342 011e 	sbfx	r1, r2, #0, #31
 8006a70:	1868      	adds	r0, r5, r1
 8006a72:	68a1      	ldr	r1, [r4, #8]
 8006a74:	4288      	cmp	r0, r1
 8006a76:	d10a      	bne.n	8006a8e <unwind_frame+0x72>
 8006a78:	e9d4 1001 	ldrd	r1, r0, [r4, #4]
 8006a7c:	4288      	cmp	r0, r1
 8006a7e:	d102      	bne.n	8006a86 <unwind_frame+0x6a>
 8006a80:	f06f 0008 	mvn.w	r0, #8
 8006a84:	e7ee      	b.n	8006a64 <unwind_frame+0x48>
 8006a86:	6860      	ldr	r0, [r4, #4]
 8006a88:	60a0      	str	r0, [r4, #8]
 8006a8a:	2000      	movs	r0, #0
 8006a8c:	e7ea      	b.n	8006a64 <unwind_frame+0x48>
 8006a8e:	6868      	ldr	r0, [r5, #4]
 8006a90:	f000 4000 	and.w	r0, r0, #2147483648	@ 0x80000000
 8006a94:	b930      	cbnz	r0, 8006aa4 <unwind_frame+0x88>
 8006a96:	686a      	ldr	r2, [r5, #4]
 8006a98:	f342 011e 	sbfx	r1, r2, #0, #31
 8006a9c:	1d2a      	adds	r2, r5, #4
 8006a9e:	1850      	adds	r0, r2, r1
 8006aa0:	9010      	str	r0, [sp, #64]	@ 0x40
 8006aa2:	e010      	b.n	8006ac6 <unwind_frame+0xaa>
 8006aa4:	6868      	ldr	r0, [r5, #4]
 8006aa6:	f000 407f 	and.w	r0, r0, #4278190080	@ 0xff000000
 8006aaa:	f1b0 4f00 	cmp.w	r0, #2147483648	@ 0x80000000
 8006aae:	d102      	bne.n	8006ab6 <unwind_frame+0x9a>
 8006ab0:	1d28      	adds	r0, r5, #4
 8006ab2:	9010      	str	r0, [sp, #64]	@ 0x40
 8006ab4:	e007      	b.n	8006ac6 <unwind_frame+0xaa>
 8006ab6:	462a      	mov	r2, r5
 8006ab8:	4837      	ldr	r0, [pc, #220]	@ (8006b98 <unwind_frame+0x17c>)
 8006aba:	6869      	ldr	r1, [r5, #4]
 8006abc:	f7ff fa40 	bl	8005f40 <__0printf$8>
 8006ac0:	f06f 0008 	mvn.w	r0, #8
 8006ac4:	e7ce      	b.n	8006a64 <unwind_frame+0x48>
 8006ac6:	9810      	ldr	r0, [sp, #64]	@ 0x40
 8006ac8:	6800      	ldr	r0, [r0, #0]
 8006aca:	f000 407f 	and.w	r0, r0, #4278190080	@ 0xff000000
 8006ace:	f1b0 4f00 	cmp.w	r0, #2147483648	@ 0x80000000
 8006ad2:	d104      	bne.n	8006ade <unwind_frame+0xc2>
 8006ad4:	2002      	movs	r0, #2
 8006ad6:	9015      	str	r0, [sp, #84]	@ 0x54
 8006ad8:	2001      	movs	r0, #1
 8006ada:	9014      	str	r0, [sp, #80]	@ 0x50
 8006adc:	e017      	b.n	8006b0e <unwind_frame+0xf2>
 8006ade:	9810      	ldr	r0, [sp, #64]	@ 0x40
 8006ae0:	6800      	ldr	r0, [r0, #0]
 8006ae2:	f000 407f 	and.w	r0, r0, #4278190080	@ 0xff000000
 8006ae6:	f1b0 4f01 	cmp.w	r0, #2164260864	@ 0x81000000
 8006aea:	d108      	bne.n	8006afe <unwind_frame+0xe2>
 8006aec:	2001      	movs	r0, #1
 8006aee:	9015      	str	r0, [sp, #84]	@ 0x54
 8006af0:	9810      	ldr	r0, [sp, #64]	@ 0x40
 8006af2:	6800      	ldr	r0, [r0, #0]
 8006af4:	f3c0 4007 	ubfx	r0, r0, #16, #8
 8006af8:	1c40      	adds	r0, r0, #1
 8006afa:	9014      	str	r0, [sp, #80]	@ 0x50
 8006afc:	e007      	b.n	8006b0e <unwind_frame+0xf2>
 8006afe:	9a10      	ldr	r2, [sp, #64]	@ 0x40
 8006b00:	a026      	add	r0, pc, #152	@ (adr r0, 8006b9c <unwind_frame+0x180>)
 8006b02:	6811      	ldr	r1, [r2, #0]
 8006b04:	f7ff fa1c 	bl	8005f40 <__0printf$8>
 8006b08:	f06f 0008 	mvn.w	r0, #8
 8006b0c:	e7aa      	b.n	8006a64 <unwind_frame+0x48>
 8006b0e:	2000      	movs	r0, #0
 8006b10:	9013      	str	r0, [sp, #76]	@ 0x4c
 8006b12:	e008      	b.n	8006b26 <unwind_frame+0x10a>
 8006b14:	4668      	mov	r0, sp
 8006b16:	f7ff fdf3 	bl	8006700 <unwind_exec_insn>
 8006b1a:	4606      	mov	r6, r0
 8006b1c:	2e00      	cmp	r6, #0
 8006b1e:	da01      	bge.n	8006b24 <unwind_frame+0x108>
 8006b20:	4630      	mov	r0, r6
 8006b22:	e79f      	b.n	8006a64 <unwind_frame+0x48>
 8006b24:	bf00      	nop
 8006b26:	9814      	ldr	r0, [sp, #80]	@ 0x50
 8006b28:	2800      	cmp	r0, #0
 8006b2a:	dcf3      	bgt.n	8006b14 <unwind_frame+0xf8>
 8006b2c:	980f      	ldr	r0, [sp, #60]	@ 0x3c
 8006b2e:	b908      	cbnz	r0, 8006b34 <unwind_frame+0x118>
 8006b30:	980e      	ldr	r0, [sp, #56]	@ 0x38
 8006b32:	900f      	str	r0, [sp, #60]	@ 0x3c
 8006b34:	68a0      	ldr	r0, [r4, #8]
 8006b36:	990f      	ldr	r1, [sp, #60]	@ 0x3c
 8006b38:	4288      	cmp	r0, r1
 8006b3a:	d106      	bne.n	8006b4a <unwind_frame+0x12e>
 8006b3c:	6820      	ldr	r0, [r4, #0]
 8006b3e:	990d      	ldr	r1, [sp, #52]	@ 0x34
 8006b40:	4288      	cmp	r0, r1
 8006b42:	d102      	bne.n	8006b4a <unwind_frame+0x12e>
 8006b44:	f06f 0008 	mvn.w	r0, #8
 8006b48:	e78c      	b.n	8006a64 <unwind_frame+0x48>
 8006b4a:	980d      	ldr	r0, [sp, #52]	@ 0x34
 8006b4c:	6020      	str	r0, [r4, #0]
 8006b4e:	980e      	ldr	r0, [sp, #56]	@ 0x38
 8006b50:	6060      	str	r0, [r4, #4]
 8006b52:	980f      	ldr	r0, [sp, #60]	@ 0x3c
 8006b54:	60a0      	str	r0, [r4, #8]
 8006b56:	9812      	ldr	r0, [sp, #72]	@ 0x48
 8006b58:	60e0      	str	r0, [r4, #12]
 8006b5a:	a002      	add	r0, pc, #8	@ (adr r0, 8006b64 <unwind_frame+0x148>)
 8006b5c:	f7ff f9f0 	bl	8005f40 <__0printf$8>
 8006b60:	2000      	movs	r0, #0
 8006b62:	e77f      	b.n	8006a64 <unwind_frame+0x48>
 8006b64:	0000000a 	.word	0x0000000a
 8006b68:	2d786469 	.word	0x2d786469
 8006b6c:	6464613e 	.word	0x6464613e
 8006b70:	666f5f72 	.word	0x666f5f72
 8006b74:	74657366 	.word	0x74657366
 8006b78:	2578303d 	.word	0x2578303d
 8006b7c:	70202c78 	.word	0x70202c78
 8006b80:	78303d63 	.word	0x78303d63
 8006b84:	202c7825 	.word	0x202c7825
 8006b88:	2d786469 	.word	0x2d786469
 8006b8c:	736e693e 	.word	0x736e693e
 8006b90:	2578303d 	.word	0x2578303d
 8006b94:	00000a78 	.word	0x00000a78
 8006b98:	08006cc4 	.word	0x08006cc4
 8006b9c:	69776e75 	.word	0x69776e75
 8006ba0:	203a646e 	.word	0x203a646e
 8006ba4:	75736e55 	.word	0x75736e55
 8006ba8:	726f7070 	.word	0x726f7070
 8006bac:	20646574 	.word	0x20646574
 8006bb0:	73726570 	.word	0x73726570
 8006bb4:	6c616e6f 	.word	0x6c616e6f
 8006bb8:	20797469 	.word	0x20797469
 8006bbc:	74756f72 	.word	0x74756f72
 8006bc0:	20656e69 	.word	0x20656e69
 8006bc4:	6c383025 	.word	0x6c383025
 8006bc8:	74612078 	.word	0x74612078
 8006bcc:	0a702520 	.word	0x0a702520
 8006bd0:	00000000 	.word	0x00000000

08006bd4 <unwind_get_byte>:
 8006bd4:	b570      	push	{r4, r5, r6, lr}
 8006bd6:	4604      	mov	r4, r0
 8006bd8:	6d20      	ldr	r0, [r4, #80]	@ 0x50
 8006bda:	2800      	cmp	r0, #0
 8006bdc:	dc04      	bgt.n	8006be8 <unwind_get_byte+0x14>
 8006bde:	a00e      	add	r0, pc, #56	@ (adr r0, 8006c18 <unwind_get_byte+0x44>)
 8006be0:	f7ff f9ae 	bl	8005f40 <__0printf$8>
 8006be4:	2000      	movs	r0, #0
 8006be6:	bd70      	pop	{r4, r5, r6, pc}
 8006be8:	6c20      	ldr	r0, [r4, #64]	@ 0x40
 8006bea:	6800      	ldr	r0, [r0, #0]
 8006bec:	f894 1054 	ldrb.w	r1, [r4, #84]	@ 0x54
 8006bf0:	00c9      	lsls	r1, r1, #3
 8006bf2:	40c8      	lsrs	r0, r1
 8006bf4:	b2c5      	uxtb	r5, r0
 8006bf6:	6d60      	ldr	r0, [r4, #84]	@ 0x54
 8006bf8:	b940      	cbnz	r0, 8006c0c <unwind_get_byte+0x38>
 8006bfa:	6c20      	ldr	r0, [r4, #64]	@ 0x40
 8006bfc:	1d00      	adds	r0, r0, #4
 8006bfe:	6420      	str	r0, [r4, #64]	@ 0x40
 8006c00:	6d20      	ldr	r0, [r4, #80]	@ 0x50
 8006c02:	1e40      	subs	r0, r0, #1
 8006c04:	6520      	str	r0, [r4, #80]	@ 0x50
 8006c06:	2003      	movs	r0, #3
 8006c08:	6560      	str	r0, [r4, #84]	@ 0x54
 8006c0a:	e002      	b.n	8006c12 <unwind_get_byte+0x3e>
 8006c0c:	6d60      	ldr	r0, [r4, #84]	@ 0x54
 8006c0e:	1e40      	subs	r0, r0, #1
 8006c10:	6560      	str	r0, [r4, #84]	@ 0x54
 8006c12:	4628      	mov	r0, r5
 8006c14:	e7e7      	b.n	8006be6 <unwind_get_byte+0x12>
 8006c16:	0000      	.short	0x0000
 8006c18:	69776e75 	.word	0x69776e75
 8006c1c:	203a646e 	.word	0x203a646e
 8006c20:	72726f43 	.word	0x72726f43
 8006c24:	20747075 	.word	0x20747075
 8006c28:	69776e75 	.word	0x69776e75
 8006c2c:	7420646e 	.word	0x7420646e
 8006c30:	656c6261 	.word	0x656c6261
 8006c34:	0000000a 	.word	0x0000000a

08006c38 <unwind_pop_register>:
 8006c38:	b510      	push	{r4, lr}
 8006c3a:	4603      	mov	r3, r0
 8006c3c:	6cd8      	ldr	r0, [r3, #76]	@ 0x4c
 8006c3e:	b130      	cbz	r0, 8006c4e <unwind_pop_register+0x16>
 8006c40:	6808      	ldr	r0, [r1, #0]
 8006c42:	6c5c      	ldr	r4, [r3, #68]	@ 0x44
 8006c44:	42a0      	cmp	r0, r4
 8006c46:	d302      	bcc.n	8006c4e <unwind_pop_register+0x16>
 8006c48:	f06f 0008 	mvn.w	r0, #8
 8006c4c:	bd10      	pop	{r4, pc}
 8006c4e:	6808      	ldr	r0, [r1, #0]
 8006c50:	6800      	ldr	r0, [r0, #0]
 8006c52:	f843 0022 	str.w	r0, [r3, r2, lsl #2]
 8006c56:	2a0e      	cmp	r2, #14
 8006c58:	d101      	bne.n	8006c5e <unwind_pop_register+0x26>
 8006c5a:	6808      	ldr	r0, [r1, #0]
 8006c5c:	6498      	str	r0, [r3, #72]	@ 0x48
 8006c5e:	6808      	ldr	r0, [r1, #0]
 8006c60:	1d00      	adds	r0, r0, #4
 8006c62:	6008      	str	r0, [r1, #0]
 8006c64:	2000      	movs	r0, #0
 8006c66:	e7f1      	b.n	8006c4c <unwind_pop_register+0x14>

08006c68 <.extab.HAL_NVIC_SetPriority>:
 8006c68:	a700 8101 b0b0 8400 0000 0000               ............

08006c74 <__func__>:
 8006c74:	6e75 6977 646e 655f 6578 5f63 6e69 6e73     unwind_exec_insn
	...

08006c85 <aPLLMULFactorTable>:
 8006c85:	0302 0504 0706 0908 0b0a 0d0c 0f0e 1010     ................

08006c95 <aPredivFactorTable>:
 8006c95:	0201                                        ..

08006c97 <aPLLMULFactorTable>:
 8006c97:	0302 0504 0706 0908 0b0a 0d0c 0f0e 1010     ................

08006ca7 <aPredivFactorTable>:
 8006ca7:	0201                                        ..

08006ca9 <AHBPrescTable>:
	...
 8006cb1:	0201 0403 0706 0908                         ........

08006cb9 <APBPrescTable>:
 8006cb9:	0000 0000 0201 0403 0000 7500 776e 6e69     ...........unwin
 8006cc9:	3a64 5520 736e 7075 6f70 7472 6465 7020     d: Unsupported p
 8006cd9:	7265 6f73 616e 696c 7974 7220 756f 6974     ersonality routi
 8006ce9:	656e 2520 3830 786c 6920 206e 6874 2065     ne %08lx in the 
 8006cf9:	6e69 6564 2078 7461 2520 0a70 0000           index at %p....

08006d08 <Region$$Table$$Base>:
 8006d08:	080071c0 	.word	0x080071c0
 8006d0c:	20000000 	.word	0x20000000
 8006d10:	00000028 	.word	0x00000028
 8006d14:	08005f98 	.word	0x08005f98
 8006d18:	080071e8 	.word	0x080071e8
 8006d1c:	20000028 	.word	0x20000028
 8006d20:	00000668 	.word	0x00000668
 8006d24:	08005fa8 	.word	0x08005fa8
