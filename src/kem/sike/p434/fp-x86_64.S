.text

.Lp434x2:
.quad	0xFFFFFFFFFFFFFFFE
.quad	0xFFFFFFFFFFFFFFFF
.quad	0xFB82ECF5C5FFFFFF
.quad	0xF78CB8F062B15D47
.quad	0xD9F8BFAD038A40AC
.quad	0x0004683E4E2EE688


.Lp434p1:
.quad	0xFDC1767AE3000000
.quad	0x7BC65C783158AEA3
.quad	0x6CFC5FD681C52056
.quad	0x0002341F27177344

.globl	sike_fpadd_asm
.hidden sike_fpadd_asm
.type	sike_fpadd_asm,@function
sike_fpadd_asm:
.cfi_startproc
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	r12, -16
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	r13, -24
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	r14, -32

	xorq	%rax,%rax

	movq	0(%rdi),%r8
	addq	0(%rsi),%r8
	movq	8(%rdi),%r9
	adcq	8(%rsi),%r9
	movq	16(%rdi),%r10
	adcq	16(%rsi),%r10
	movq	24(%rdi),%r11
	adcq	24(%rsi),%r11
	movq	32(%rdi),%r12
	adcq	32(%rsi),%r12
	movq	40(%rdi),%r13
	adcq	40(%rsi),%r13
	movq	48(%rdi),%r14
	adcq	48(%rsi),%r14

	movq	.Lp434x2(%rip),%rcx
	subq	%rcx,%r8
	movq	8+.Lp434x2(%rip),%rcx
	sbbq	%rcx,%r9
	sbbq	%rcx,%r10
	movq	16+.Lp434x2(%rip),%rcx
	sbbq	%rcx,%r11
	movq	24+.Lp434x2(%rip),%rcx
	sbbq	%rcx,%r12
	movq	32+.Lp434x2(%rip),%rcx
	sbbq	%rcx,%r13
	movq	40+.Lp434x2(%rip),%rcx
	sbbq	%rcx,%r14

	sbbq	$0,%rax

	movq	.Lp434x2(%rip),%rdi
	andq	%rax,%rdi
	movq	8+.Lp434x2(%rip),%rsi
	andq	%rax,%rsi
	movq	16+.Lp434x2(%rip),%rcx
	andq	%rax,%rcx

	addq	%rdi,%r8
	movq	%r8,0(%rdx)
	adcq	%rsi,%r9
	movq	%r9,8(%rdx)
	adcq	%rsi,%r10
	movq	%r10,16(%rdx)
	adcq	%rcx,%r11
	movq	%r11,24(%rdx)

	setc	%cl
	movq	24+.Lp434x2(%rip),%r8
	andq	%rax,%r8
	movq	32+.Lp434x2(%rip),%r9
	andq	%rax,%r9
	movq	40+.Lp434x2(%rip),%r10
	andq	%rax,%r10
	btq	$0,%rcx

	adcq	%r8,%r12
	movq	%r12,32(%rdx)
	adcq	%r9,%r13
	movq	%r13,40(%rdx)
	adcq	%r10,%r14
	movq	%r14,48(%rdx)

	popq	%r14
.cfi_adjust_cfa_offset	-8
	popq	%r13
.cfi_adjust_cfa_offset	-8
	popq	%r12
.cfi_adjust_cfa_offset	-8
	.byte	0xf3,0xc3
.cfi_endproc

.globl	sike_fpsub_asm
.hidden sike_fpsub_asm
.type	sike_fpsub_asm,@function
sike_fpsub_asm:
.cfi_startproc
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	r12, -16
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	r13, -24
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	r14, -32

	xorq	%rax,%rax

	movq	0(%rdi),%r8
	subq	0(%rsi),%r8
	movq	8(%rdi),%r9
	sbbq	8(%rsi),%r9
	movq	16(%rdi),%r10
	sbbq	16(%rsi),%r10
	movq	24(%rdi),%r11
	sbbq	24(%rsi),%r11
	movq	32(%rdi),%r12
	sbbq	32(%rsi),%r12
	movq	40(%rdi),%r13
	sbbq	40(%rsi),%r13
	movq	48(%rdi),%r14
	sbbq	48(%rsi),%r14

	sbbq	$0x0,%rax

	movq	.Lp434x2(%rip),%rdi
	andq	%rax,%rdi
	movq	8+.Lp434x2(%rip),%rsi
	andq	%rax,%rsi
	movq	16+.Lp434x2(%rip),%rcx
	andq	%rax,%rcx

	addq	%rdi,%r8
	movq	%r8,0(%rdx)
	adcq	%rsi,%r9
	movq	%r9,8(%rdx)
	adcq	%rsi,%r10
	movq	%r10,16(%rdx)
	adcq	%rcx,%r11
	movq	%r11,24(%rdx)

	setc	%cl
	movq	24+.Lp434x2(%rip),%r8
	andq	%rax,%r8
	movq	32+.Lp434x2(%rip),%r9
	andq	%rax,%r9
	movq	40+.Lp434x2(%rip),%r10
	andq	%rax,%r10
	btq	$0x0,%rcx

	adcq	%r8,%r12
	adcq	%r9,%r13
	adcq	%r10,%r14
	movq	%r12,32(%rdx)
	movq	%r13,40(%rdx)
	movq	%r14,48(%rdx)

	popq	%r14
.cfi_adjust_cfa_offset	-8
	popq	%r13
.cfi_adjust_cfa_offset	-8
	popq	%r12
.cfi_adjust_cfa_offset	-8
	.byte	0xf3,0xc3
.cfi_endproc
.globl	sike_mpadd_asm
.hidden sike_mpadd_asm
.type	sike_mpadd_asm,@function
sike_mpadd_asm:
.cfi_startproc
	movq	0(%rdi),%r8;
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%rcx
	addq	0(%rsi),%r8
	adcq	8(%rsi),%r9
	adcq	16(%rsi),%r10
	adcq	24(%rsi),%r11
	adcq	32(%rsi),%rcx
	movq	%r8,0(%rdx)
	movq	%r9,8(%rdx)
	movq	%r10,16(%rdx)
	movq	%r11,24(%rdx)
	movq	%rcx,32(%rdx)

	movq	40(%rdi),%r8
	movq	48(%rdi),%r9
	adcq	40(%rsi),%r8
	adcq	48(%rsi),%r9
	movq	%r8,40(%rdx)
	movq	%r9,48(%rdx)
	.byte	0xf3,0xc3
.cfi_endproc
.globl	sike_mpsubx2_asm
.hidden sike_mpsubx2_asm
.type	sike_mpsubx2_asm,@function
sike_mpsubx2_asm:
.cfi_startproc
	xorq	%rax,%rax

	movq	0(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%rcx
	subq	0(%rsi),%r8
	sbbq	8(%rsi),%r9
	sbbq	16(%rsi),%r10
	sbbq	24(%rsi),%r11
	sbbq	32(%rsi),%rcx
	movq	%r8,0(%rdx)
	movq	%r9,8(%rdx)
	movq	%r10,16(%rdx)
	movq	%r11,24(%rdx)
	movq	%rcx,32(%rdx)

	movq	40(%rdi),%r8
	movq	48(%rdi),%r9
	movq	56(%rdi),%r10
	movq	64(%rdi),%r11
	movq	72(%rdi),%rcx
	sbbq	40(%rsi),%r8
	sbbq	48(%rsi),%r9
	sbbq	56(%rsi),%r10
	sbbq	64(%rsi),%r11
	sbbq	72(%rsi),%rcx
	movq	%r8,40(%rdx)
	movq	%r9,48(%rdx)
	movq	%r10,56(%rdx)
	movq	%r11,64(%rdx)
	movq	%rcx,72(%rdx)

	movq	80(%rdi),%r8
	movq	88(%rdi),%r9
	movq	96(%rdi),%r10
	movq	104(%rdi),%r11
	sbbq	80(%rsi),%r8
	sbbq	88(%rsi),%r9
	sbbq	96(%rsi),%r10
	sbbq	104(%rsi),%r11
	sbbq	$0x0,%rax
	movq	%r8,80(%rdx)
	movq	%r9,88(%rdx)
	movq	%r10,96(%rdx)
	movq	%r11,104(%rdx)
	.byte	0xf3,0xc3
.cfi_endproc
.globl	sike_mpdblsubx2_asm
.hidden sike_mpdblsubx2_asm
.type	sike_mpdblsubx2_asm,@function
sike_mpdblsubx2_asm:
.cfi_startproc
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	r12, -16
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	r13, -24

	xorq	%rax,%rax


	movq	0(%rdx),%r8
	movq	8(%rdx),%r9
	movq	16(%rdx),%r10
	movq	24(%rdx),%r11
	movq	32(%rdx),%r12
	movq	40(%rdx),%r13
	movq	48(%rdx),%rcx
	subq	0(%rdi),%r8
	sbbq	8(%rdi),%r9
	sbbq	16(%rdi),%r10
	sbbq	24(%rdi),%r11
	sbbq	32(%rdi),%r12
	sbbq	40(%rdi),%r13
	sbbq	48(%rdi),%rcx
	adcq	$0x0,%rax


	subq	0(%rsi),%r8
	sbbq	8(%rsi),%r9
	sbbq	16(%rsi),%r10
	sbbq	24(%rsi),%r11
	sbbq	32(%rsi),%r12
	sbbq	40(%rsi),%r13
	sbbq	48(%rsi),%rcx
	adcq	$0x0,%rax


	movq	%r8,0(%rdx)
	movq	%r9,8(%rdx)
	movq	%r10,16(%rdx)
	movq	%r11,24(%rdx)
	movq	%r12,32(%rdx)
	movq	%r13,40(%rdx)
	movq	%rcx,48(%rdx)


	movq	56(%rdx),%r8
	movq	64(%rdx),%r9
	movq	72(%rdx),%r10
	movq	80(%rdx),%r11
	movq	88(%rdx),%r12
	movq	96(%rdx),%r13
	movq	104(%rdx),%rcx

	subq	%rax,%r8
	sbbq	56(%rdi),%r8
	sbbq	64(%rdi),%r9
	sbbq	72(%rdi),%r10
	sbbq	80(%rdi),%r11
	sbbq	88(%rdi),%r12
	sbbq	96(%rdi),%r13
	sbbq	104(%rdi),%rcx


	subq	56(%rsi),%r8
	sbbq	64(%rsi),%r9
	sbbq	72(%rsi),%r10
	sbbq	80(%rsi),%r11
	sbbq	88(%rsi),%r12
	sbbq	96(%rsi),%r13
	sbbq	104(%rsi),%rcx


	movq	%r8,56(%rdx)
	movq	%r9,64(%rdx)
	movq	%r10,72(%rdx)
	movq	%r11,80(%rdx)
	movq	%r12,88(%rdx)
	movq	%r13,96(%rdx)
	movq	%rcx,104(%rdx)

	popq	%r13
.cfi_adjust_cfa_offset	-8
	popq	%r12
.cfi_adjust_cfa_offset	-8
	.byte	0xf3,0xc3
.cfi_endproc

.globl	sike_fprdc_asm
.hidden sike_fprdc_asm
.type	sike_fprdc_asm,@function
sike_fprdc_asm:
.cfi_startproc
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	r12, -16
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	r13, -24
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	r14, -32
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	r15, -40

	xorq	%rax,%rax
	movq	0+0(%rdi),%rdx
	mulxq	0+.Lp434p1(%rip),%r8,%r9
	mulxq	8+.Lp434p1(%rip),%r12,%r10
	mulxq	16+.Lp434p1(%rip),%r13,%r11

	adoxq	%r12,%r9
	adoxq	%r13,%r10

	mulxq	24+.Lp434p1(%rip),%r13,%r12
	adoxq	%r13,%r11
	adoxq	%rax,%r12

	xorq	%rax,%rax
	movq	0+8(%rdi),%rdx
	mulxq	0+.Lp434p1(%rip),%r13,%rcx
	adcxq	%r13,%r9
	adcxq	%rcx,%r10

	mulxq	8+.Lp434p1(%rip),%rcx,%r13
	adcxq	%r13,%r11
	adoxq	%rcx,%r10

	mulxq	16+.Lp434p1(%rip),%rcx,%r13
	adcxq	%r13,%r12
	adoxq	%rcx,%r11

	mulxq	24+.Lp434p1(%rip),%rcx,%r13
	adcxq	%rax,%r13
	adoxq	%rcx,%r12
	adoxq	%rax,%r13

	xorq	%rcx,%rcx
	addq	24(%rdi),%r8
	adcq	32(%rdi),%r9
	adcq	40(%rdi),%r10
	adcq	48(%rdi),%r11
	adcq	56(%rdi),%r12
	adcq	64(%rdi),%r13
	adcq	72(%rdi),%rcx
	movq	%r8,24(%rdi)
	movq	%r9,32(%rdi)
	movq	%r10,40(%rdi)
	movq	%r11,48(%rdi)
	movq	%r12,56(%rdi)
	movq	%r13,64(%rdi)
	movq	%rcx,72(%rdi)
	movq	80(%rdi),%r8
	movq	88(%rdi),%r9
	movq	96(%rdi),%r10
	movq	104(%rdi),%r11
	adcq	$0x0,%r8
	adcq	$0x0,%r9
	adcq	$0x0,%r10
	adcq	$0x0,%r11
	movq	%r8,80(%rdi)
	movq	%r9,88(%rdi)
	movq	%r10,96(%rdi)
	movq	%r11,104(%rdi)

	xorq	%rax,%rax
	movq	16+0(%rdi),%rdx
	mulxq	0+.Lp434p1(%rip),%r8,%r9
	mulxq	8+.Lp434p1(%rip),%r12,%r10
	mulxq	16+.Lp434p1(%rip),%r13,%r11

	adoxq	%r12,%r9
	adoxq	%r13,%r10

	mulxq	24+.Lp434p1(%rip),%r13,%r12
	adoxq	%r13,%r11
	adoxq	%rax,%r12

	xorq	%rax,%rax
	movq	16+8(%rdi),%rdx
	mulxq	0+.Lp434p1(%rip),%r13,%rcx
	adcxq	%r13,%r9
	adcxq	%rcx,%r10

	mulxq	8+.Lp434p1(%rip),%rcx,%r13
	adcxq	%r13,%r11
	adoxq	%rcx,%r10

	mulxq	16+.Lp434p1(%rip),%rcx,%r13
	adcxq	%r13,%r12
	adoxq	%rcx,%r11

	mulxq	24+.Lp434p1(%rip),%rcx,%r13
	adcxq	%rax,%r13
	adoxq	%rcx,%r12
	adoxq	%rax,%r13

	xorq	%rcx,%rcx
	addq	40(%rdi),%r8
	adcq	48(%rdi),%r9
	adcq	56(%rdi),%r10
	adcq	64(%rdi),%r11
	adcq	72(%rdi),%r12
	adcq	80(%rdi),%r13
	adcq	88(%rdi),%rcx
	movq	%r8,40(%rdi)
	movq	%r9,48(%rdi)
	movq	%r10,56(%rdi)
	movq	%r11,64(%rdi)
	movq	%r12,72(%rdi)
	movq	%r13,80(%rdi)
	movq	%rcx,88(%rdi)
	movq	96(%rdi),%r8
	movq	104(%rdi),%r9
	adcq	$0x0,%r8
	adcq	$0x0,%r9
	movq	%r8,96(%rdi)
	movq	%r9,104(%rdi)

	xorq	%rax,%rax
	movq	32+0(%rdi),%rdx
	mulxq	0+.Lp434p1(%rip),%r8,%r9
	mulxq	8+.Lp434p1(%rip),%r12,%r10
	mulxq	16+.Lp434p1(%rip),%r13,%r11

	adoxq	%r12,%r9
	adoxq	%r13,%r10

	mulxq	24+.Lp434p1(%rip),%r13,%r12
	adoxq	%r13,%r11
	adoxq	%rax,%r12

	xorq	%rax,%rax
	movq	32+8(%rdi),%rdx
	mulxq	0+.Lp434p1(%rip),%r13,%rcx
	adcxq	%r13,%r9
	adcxq	%rcx,%r10

	mulxq	8+.Lp434p1(%rip),%rcx,%r13
	adcxq	%r13,%r11
	adoxq	%rcx,%r10

	mulxq	16+.Lp434p1(%rip),%rcx,%r13
	adcxq	%r13,%r12
	adoxq	%rcx,%r11

	mulxq	24+.Lp434p1(%rip),%rcx,%r13
	adcxq	%rax,%r13
	adoxq	%rcx,%r12
	adoxq	%rax,%r13

	xorq	%rcx,%rcx
	addq	56(%rdi),%r8
	adcq	64(%rdi),%r9
	adcq	72(%rdi),%r10
	adcq	80(%rdi),%r11
	adcq	88(%rdi),%r12
	adcq	96(%rdi),%r13
	adcq	104(%rdi),%rcx
	movq	%r8,0(%rsi)
	movq	%r9,8(%rsi)
	movq	%r10,72(%rdi)
	movq	%r11,80(%rdi)
	movq	%r12,88(%rdi)
	movq	%r13,96(%rdi)
	movq	%rcx,104(%rdi)

	xorq	%rax,%rax
	movq	48(%rdi),%rdx
	mulxq	0+.Lp434p1(%rip),%r8,%r9
	mulxq	8+.Lp434p1(%rip),%r12,%r10
	mulxq	16+.Lp434p1(%rip),%r13,%r11

	adoxq	%r12,%r9
	adoxq	%r13,%r10

	mulxq	24+.Lp434p1(%rip),%r13,%r12
	adoxq	%r13,%r11
	adoxq	%rax,%r12

	addq	72(%rdi),%r8
	adcq	80(%rdi),%r9
	adcq	88(%rdi),%r10
	adcq	96(%rdi),%r11
	adcq	104(%rdi),%r12
	movq	%r8,16(%rsi)
	movq	%r9,24(%rsi)
	movq	%r10,32(%rsi)
	movq	%r11,40(%rsi)
	movq	%r12,48(%rsi)


	popq	%r15
.cfi_adjust_cfa_offset	-8
	popq	%r14
.cfi_adjust_cfa_offset	-8
	popq	%r13
.cfi_adjust_cfa_offset	-8
	popq	%r12
.cfi_adjust_cfa_offset	-8
	.byte	0xf3,0xc3
.cfi_endproc
.globl	sike_mpmul_asm
.hidden sike_mpmul_asm
.type	sike_mpmul_asm,@function
sike_mpmul_asm:
.cfi_startproc
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	r12, -16
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	r13, -24
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	r14, -32
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	r15, -40


	movq	%rdx,%rcx
	xorq	%rax,%rax


	movq	0(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11

	pushq	%rbx
.cfi_adjust_cfa_offset	8
.cfi_offset	rbx, -48
	pushq	%rbp
.cfi_offset	rbp, -56
.cfi_adjust_cfa_offset	8
	subq	$96,%rsp
.cfi_adjust_cfa_offset	96

	addq	32(%rdi),%r8
	adcq	40(%rdi),%r9
	adcq	48(%rdi),%r10
	adcq	$0x0,%r11
	sbbq	$0x0,%rax
	movq	%r8,0(%rsp)
	movq	%r9,8(%rsp)
	movq	%r10,16(%rsp)
	movq	%r11,24(%rsp)


	xorq	%rbx,%rbx
	movq	0(%rsi),%r12
	movq	8(%rsi),%r13
	movq	16(%rsi),%r14
	movq	24(%rsi),%r15
	addq	32(%rsi),%r12
	adcq	40(%rsi),%r13
	adcq	48(%rsi),%r14
	adcq	$0x0,%r15
	sbbq	$0x0,%rbx
	movq	%r12,32(%rsp)
	movq	%r13,40(%rsp)
	movq	%r14,48(%rsp)
	movq	%r15,56(%rsp)


	andq	%rax,%r12
	andq	%rax,%r13
	andq	%rax,%r14
	andq	%rax,%r15


	andq	%rbx,%r8
	andq	%rbx,%r9
	andq	%rbx,%r10
	andq	%rbx,%r11


	addq	%r12,%r8
	adcq	%r13,%r9
	adcq	%r14,%r10
	adcq	%r15,%r11
	movq	%r8,64(%rsp)
	movq	%r9,72(%rsp)
	movq	%r10,80(%rsp)
	movq	%r11,88(%rsp)


	movq	0+0(%rsp),%rdx
	mulxq	32+0(%rsp),%r9,%r8
	movq	%r9,0+0(%rsp)
	mulxq	32+8(%rsp),%r10,%r9
	xorq	%rax,%rax
	adoxq	%r10,%r8
	mulxq	32+16(%rsp),%r11,%r10
	adoxq	%r11,%r9
	mulxq	32+24(%rsp),%r12,%r11
	adoxq	%r12,%r10

	movq	0+8(%rsp),%rdx
	mulxq	32+0(%rsp),%r12,%r13
	adoxq	%rax,%r11
	xorq	%rax,%rax
	mulxq	32+8(%rsp),%r15,%r14
	adoxq	%r8,%r12
	movq	%r12,0+8(%rsp)
	adcxq	%r15,%r13
	mulxq	32+16(%rsp),%rbx,%r15
	adcxq	%rbx,%r14
	adoxq	%r9,%r13
	mulxq	32+24(%rsp),%rbp,%rbx
	adcxq	%rbp,%r15
	adcxq	%rax,%rbx
	adoxq	%r10,%r14

	movq	0+16(%rsp),%rdx
	mulxq	32+0(%rsp),%r8,%r9
	adoxq	%r11,%r15
	adoxq	%rax,%rbx
	xorq	%rax,%rax
	mulxq	32+8(%rsp),%r11,%r10
	adoxq	%r13,%r8
	movq	%r8,0+16(%rsp)
	adcxq	%r11,%r9
	mulxq	32+16(%rsp),%r12,%r11
	adcxq	%r12,%r10
	adoxq	%r14,%r9
	mulxq	32+24(%rsp),%rbp,%r12
	adcxq	%rbp,%r11
	adcxq	%rax,%r12

	adoxq	%r15,%r10
	adoxq	%rbx,%r11
	adoxq	%rax,%r12

	movq	0+24(%rsp),%rdx
	mulxq	32+0(%rsp),%r8,%r13
	xorq	%rax,%rax
	mulxq	32+8(%rsp),%r15,%r14
	adcxq	%r15,%r13
	adoxq	%r8,%r9
	mulxq	32+16(%rsp),%rbx,%r15
	adcxq	%rbx,%r14
	adoxq	%r13,%r10
	mulxq	32+24(%rsp),%rbp,%rbx
	adcxq	%rbp,%r15
	adcxq	%rax,%rbx
	adoxq	%r14,%r11
	adoxq	%r15,%r12
	adoxq	%rax,%rbx
	movq	%r9,0+24(%rsp)
	movq	%r10,0+32(%rsp)
	movq	%r11,0+40(%rsp)
	movq	%r12,0+48(%rsp)
	movq	%rbx,0+56(%rsp)



	movq	0+0(%rdi),%rdx
	mulxq	0+0(%rsi),%r9,%r8
	movq	%r9,0+0(%rcx)
	mulxq	0+8(%rsi),%r10,%r9
	xorq	%rax,%rax
	adoxq	%r10,%r8
	mulxq	0+16(%rsi),%r11,%r10
	adoxq	%r11,%r9
	mulxq	0+24(%rsi),%r12,%r11
	adoxq	%r12,%r10

	movq	0+8(%rdi),%rdx
	mulxq	0+0(%rsi),%r12,%r13
	adoxq	%rax,%r11
	xorq	%rax,%rax
	mulxq	0+8(%rsi),%r15,%r14
	adoxq	%r8,%r12
	movq	%r12,0+8(%rcx)
	adcxq	%r15,%r13
	mulxq	0+16(%rsi),%rbx,%r15
	adcxq	%rbx,%r14
	adoxq	%r9,%r13
	mulxq	0+24(%rsi),%rbp,%rbx
	adcxq	%rbp,%r15
	adcxq	%rax,%rbx
	adoxq	%r10,%r14

	movq	0+16(%rdi),%rdx
	mulxq	0+0(%rsi),%r8,%r9
	adoxq	%r11,%r15
	adoxq	%rax,%rbx
	xorq	%rax,%rax
	mulxq	0+8(%rsi),%r11,%r10
	adoxq	%r13,%r8
	movq	%r8,0+16(%rcx)
	adcxq	%r11,%r9
	mulxq	0+16(%rsi),%r12,%r11
	adcxq	%r12,%r10
	adoxq	%r14,%r9
	mulxq	0+24(%rsi),%rbp,%r12
	adcxq	%rbp,%r11
	adcxq	%rax,%r12

	adoxq	%r15,%r10
	adoxq	%rbx,%r11
	adoxq	%rax,%r12

	movq	0+24(%rdi),%rdx
	mulxq	0+0(%rsi),%r8,%r13
	xorq	%rax,%rax
	mulxq	0+8(%rsi),%r15,%r14
	adcxq	%r15,%r13
	adoxq	%r8,%r9
	mulxq	0+16(%rsi),%rbx,%r15
	adcxq	%rbx,%r14
	adoxq	%r13,%r10
	mulxq	0+24(%rsi),%rbp,%rbx
	adcxq	%rbp,%r15
	adcxq	%rax,%rbx
	adoxq	%r14,%r11
	adoxq	%r15,%r12
	adoxq	%rax,%rbx
	movq	%r9,0+24(%rcx)
	movq	%r10,0+32(%rcx)
	movq	%r11,0+40(%rcx)
	movq	%r12,0+48(%rcx)
	movq	%rbx,0+56(%rcx)



	movq	32+0(%rdi),%rdx
	mulxq	32+0(%rsi),%r9,%r8
	movq	%r9,64+0(%rcx)
	mulxq	32+8(%rsi),%r10,%r9
	xorq	%rax,%rax
	adoxq	%r10,%r8
	mulxq	32+16(%rsi),%r11,%r10
	adoxq	%r11,%r9

	movq	32+8(%rdi),%rdx
	mulxq	32+0(%rsi),%r12,%r11
	adoxq	%rax,%r10
	xorq	%rax,%rax

	mulxq	32+8(%rsi),%r14,%r13
	adoxq	%r8,%r12
	movq	%r12,64+8(%rcx)
	adcxq	%r14,%r11

	mulxq	32+16(%rsi),%r8,%r14
	adoxq	%r9,%r11
	adcxq	%r8,%r13
	adcxq	%rax,%r14
	adoxq	%r10,%r13

	movq	32+16(%rdi),%rdx
	mulxq	32+0(%rsi),%r8,%r9
	adoxq	%rax,%r14
	xorq	%rax,%rax

	mulxq	32+8(%rsi),%r10,%r12
	adoxq	%r11,%r8
	movq	%r8,64+16(%rcx)
	adcxq	%r13,%r9

	mulxq	32+16(%rsi),%r11,%r8
	adcxq	%r14,%r12
	adcxq	%rax,%r8
	adoxq	%r10,%r9
	adoxq	%r12,%r11
	adoxq	%rax,%r8
	movq	%r9,64+24(%rcx)
	movq	%r11,64+32(%rcx)
	movq	%r8,64+40(%rcx)




	movq	64(%rsp),%r8
	movq	72(%rsp),%r9
	movq	80(%rsp),%r10
	movq	88(%rsp),%r11

	movq	32(%rsp),%rax
	addq	%rax,%r8
	movq	40(%rsp),%rax
	adcq	%rax,%r9
	movq	48(%rsp),%rax
	adcq	%rax,%r10
	movq	56(%rsp),%rax
	adcq	%rax,%r11


	movq	0(%rsp),%r12
	movq	8(%rsp),%r13
	movq	16(%rsp),%r14
	movq	24(%rsp),%r15
	subq	0(%rcx),%r12
	sbbq	8(%rcx),%r13
	sbbq	16(%rcx),%r14
	sbbq	24(%rcx),%r15
	sbbq	32(%rcx),%r8
	sbbq	40(%rcx),%r9
	sbbq	48(%rcx),%r10
	sbbq	56(%rcx),%r11


	subq	64(%rcx),%r12
	sbbq	72(%rcx),%r13
	sbbq	80(%rcx),%r14
	sbbq	88(%rcx),%r15
	sbbq	96(%rcx),%r8
	sbbq	104(%rcx),%r9
	sbbq	$0x0,%r10
	sbbq	$0x0,%r11

	addq	32(%rcx),%r12
	movq	%r12,32(%rcx)
	adcq	40(%rcx),%r13
	movq	%r13,40(%rcx)
	adcq	48(%rcx),%r14
	movq	%r14,48(%rcx)
	adcq	56(%rcx),%r15
	movq	%r15,56(%rcx)
	adcq	64(%rcx),%r8
	movq	%r8,64(%rcx)
	adcq	72(%rcx),%r9
	movq	%r9,72(%rcx)
	adcq	80(%rcx),%r10
	movq	%r10,80(%rcx)
	adcq	88(%rcx),%r11
	movq	%r11,88(%rcx)
	movq	96(%rcx),%r12
	adcq	$0x0,%r12
	movq	%r12,96(%rcx)
	movq	104(%rcx),%r13
	adcq	$0x0,%r13
	movq	%r13,104(%rcx)

	addq	$96,%rsp
.cfi_adjust_cfa_offset	-96
	popq	%rbp
.cfi_adjust_cfa_offset	-8
.cfi_same_value	rbp
	popq	%rbx
.cfi_adjust_cfa_offset	-8
.cfi_same_value	rbx


	popq	%r15
.cfi_adjust_cfa_offset	-8
	popq	%r14
.cfi_adjust_cfa_offset	-8
	popq	%r13
.cfi_adjust_cfa_offset	-8
	popq	%r12
.cfi_adjust_cfa_offset	-8
	.byte	0xf3,0xc3
.cfi_endproc
