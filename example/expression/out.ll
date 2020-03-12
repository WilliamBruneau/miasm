; ModuleID = "mod"
target triple = "unknown-unknown-unknown"
target datalayout = ""

declare i8 @"llvm.ctpop.i8"(i8 %".1") readonly

declare float @"llvm.nearbyint.f32"(float %".1") readonly

declare double @"llvm.nearbyint.f64"(double %".1") readonly

declare float @"llvm.trunc.f32"(float %".1") readonly

declare i64 @"segm2addr"(i8* %".1", i64 %".2", i64 %".3") readonly

declare i64 @"x86_cpuid"(i64 %".1", i64 %".2") readonly

declare i64 @"fpu_fcom_c0"(double %".1", double %".2") readonly

declare i64 @"fpu_fcom_c1"(double %".1", double %".2") readonly

declare i64 @"fpu_fcom_c2"(double %".1", double %".2") readonly

declare i64 @"fpu_fcom_c3"(double %".1", double %".2") readonly

declare float @"llvm.sqrt.f32"(float %".1") readonly

declare double @"llvm.sqrt.f64"(double %".1") readonly

declare float @"llvm.fabs.f32"(float %".1") readonly

declare double @"llvm.fabs.f64"(double %".1") readonly

declare i8 @"bcdadd_8"(i8 %".1", i8 %".2") readonly

declare i8 @"bcdadd_cf_8"(i8 %".1", i8 %".2") readonly

declare i16 @"bcdadd_16"(i16 %".1", i16 %".2") readonly

declare i16 @"bcdadd_cf_16"(i16 %".1", i16 %".2") readonly

define void @"test"() 
{
entry:
  %".2" = load i32, i32* @"IRDst"
  %"IRDst" = alloca i32
  store i32 %".2", i32* %"IRDst"
  %".4" = load i1, i1* @"pf"
  %"pf" = alloca i1
  store i1 %".4", i1* %"pf"
  %".6" = load i1, i1* @"af"
  %"af" = alloca i1
  store i1 %".6", i1* %"af"
  %".8" = load i32, i32* @"ESP"
  %"ESP" = alloca i32
  store i32 %".8", i32* %"ESP"
  %".10" = load i32, i32* @"EAX"
  %"EAX" = alloca i32
  store i32 %".10", i32* %"EAX"
  %".12" = load i1, i1* @"nf"
  %"nf" = alloca i1
  store i1 %".12", i1* %"nf"
  %".14" = load i32, i32* @"EBX"
  %"EBX" = alloca i32
  store i32 %".14", i32* %"EBX"
  %".16" = load i32, i32* @"EBP"
  %"EBP" = alloca i32
  store i32 %".16", i32* %"EBP"
  %".18" = load i1, i1* @"zf"
  %"zf" = alloca i1
  store i1 %".18", i1* %"zf"
  %".20" = load i1, i1* @"of"
  %"of" = alloca i1
  store i1 %".20", i1* %"of"
  %".22" = load i32, i32* @"EDX"
  %"EDX" = alloca i32
  store i32 %".22", i32* %"EDX"
  %".24" = load i1, i1* @"cf"
  %"cf" = alloca i1
  store i1 %".24", i1* %"cf"
  br label %"loc_key_0"
exit:
  %".237" = load i32, i32* %"IRDst"
  store i32 %".237", i32* @"IRDst"
  %".239" = load i1, i1* %"pf"
  store i1 %".239", i1* @"pf"
  %".241" = load i1, i1* %"af"
  store i1 %".241", i1* @"af"
  %".243" = load i32, i32* %"ESP"
  store i32 %".243", i32* @"ESP"
  %".245" = load i32, i32* %"EAX"
  store i32 %".245", i32* @"EAX"
  %".247" = load i1, i1* %"nf"
  store i1 %".247", i1* @"nf"
  %".249" = load i32, i32* %"EBX"
  store i32 %".249", i32* @"EBX"
  %".251" = load i32, i32* %"EBP"
  store i32 %".251", i32* @"EBP"
  %".253" = load i1, i1* %"zf"
  store i1 %".253", i1* @"zf"
  %".255" = load i1, i1* %"of"
  store i1 %".255", i1* @"of"
  %".257" = load i32, i32* %"EDX"
  store i32 %".257", i32* @"EDX"
  %".259" = load i1, i1* %"cf"
  store i1 %".259", i1* @"cf"
  ret void
loc_key_0:
  %"EBP.1" = load i32, i32* %"EBP"
  %".26" = sub i32 0, 1
  %".27" = add i32 %"EBP.1", %".26"
  %".28" = icmp ne i32 %".27", 0
  %".29" = select i1 %".28", i1 0, i1 1
  %".30" = lshr i32 %".27", 31
  %".31" = and i32 %".30", 1
  %".32" = trunc i32 %".31" to i1
  %".33" = and i32 %".27", 255
  %".34" = trunc i32 %".33" to i8
  %".35" = call i8 @"llvm.ctpop.i8"(i8 %".34")
  %".36" = trunc i8 %".35" to i1
  %".37" = xor i1 %".36", -1
  %".38" = xor i32 %"EBP.1", %".27"
  %".39" = xor i32 %".38", 1
  %".40" = lshr i32 %".39", 4
  %".41" = and i32 %".40", 1
  %".42" = trunc i32 %".41" to i1
  %".43" = xor i32 %"EBP.1", %".27"
  %".44" = xor i32 %"EBP.1", 1
  %".45" = and i32 %".43", %".44"
  %".46" = lshr i32 %".45", 31
  %".47" = and i32 %".46", 1
  %".48" = trunc i32 %".47" to i1
  store i1 %".29", i1* %"zf"
  store i1 %".32", i1* %"nf"
  store i1 %".37", i1* %"pf"
  store i1 %".42", i1* %"af"
  store i1 %".48", i1* %"of"
  store i32 %".27", i32* %"EBP"
  %"ESP.1" = load i32, i32* %"ESP"
  %".55" = inttoptr i32 %"ESP.1" to i32*
  %".56" = load i32, i32* %".55"
  %".57" = add i32 %"ESP.1", 4
  store i32 %".57", i32* %"ESP"
  store i32 %".56", i32* %"EDX"
  %"EBX.1" = load i32, i32* %"EBX"
  %".60" = inttoptr i32 %"EBX.1" to i8*
  %".61" = load i8, i8* %".60"
  %"EAX.1" = load i32, i32* %"EAX"
  %".62" = and i32 %"EAX.1", 255
  %".63" = trunc i32 %".62" to i8
  %".64" = sub i8 0, %".63"
  %".65" = sub i8 0, %".64"
  %".66" = add i8 %".61", %".65"
  %".67" = icmp ne i8 %".66", 0
  %".68" = select i1 %".67", i1 0, i1 1
  %".69" = lshr i8 %".66", 7
  %".70" = and i8 %".69", 1
  %".71" = trunc i8 %".70" to i1
  %".72" = add i8 %".61", %".63"
  %".73" = and i8 %".72", 255
  %".74" = call i8 @"llvm.ctpop.i8"(i8 %".73")
  %".75" = trunc i8 %".74" to i1
  %".76" = xor i1 %".75", -1
  %".77" = xor i8 %".61", %".72"
  %".78" = xor i8 %".61", %".63"
  %".79" = xor i8 %".78", 255
  %".80" = and i8 %".77", %".79"
  %".81" = xor i8 %".61", %".80"
  %".82" = xor i8 %".81", %".72"
  %".83" = xor i8 %".82", %".63"
  %".84" = lshr i8 %".83", 7
  %".85" = and i8 %".84", 1
  %".86" = trunc i8 %".85" to i1
  %".87" = lshr i8 %".80", 7
  %".88" = and i8 %".87", 1
  %".89" = trunc i8 %".88" to i1
  %".90" = xor i8 %".61", %".72"
  %".91" = xor i8 %".90", %".63"
  %".92" = lshr i8 %".91", 4
  %".93" = and i8 %".92", 1
  %".94" = trunc i8 %".93" to i1
  %".95" = inttoptr i32 %"EBX.1" to i8*
  store i8 %".72", i8* %".95"
  store i1 %".68", i1* %"zf"
  store i1 %".71", i1* %"nf"
  store i1 %".76", i1* %"pf"
  store i1 %".86", i1* %"cf"
  store i1 %".89", i1* %"of"
  store i1 %".94", i1* %"af"
  %"EAX.2" = load i32, i32* %"EAX"
  %".103" = inttoptr i32 %"EAX.2" to i8*
  %".104" = load i8, i8* %".103"
  %".105" = and i32 %"EAX.2", 255
  %".106" = trunc i32 %".105" to i8
  %".107" = sub i8 0, %".106"
  %".108" = sub i8 0, %".107"
  %".109" = add i8 %".104", %".108"
  %".110" = icmp ne i8 %".109", 0
  %".111" = select i1 %".110", i1 0, i1 1
  %".112" = lshr i8 %".109", 7
  %".113" = and i8 %".112", 1
  %".114" = trunc i8 %".113" to i1
  %".115" = add i8 %".104", %".106"
  %".116" = and i8 %".115", 255
  %".117" = call i8 @"llvm.ctpop.i8"(i8 %".116")
  %".118" = trunc i8 %".117" to i1
  %".119" = xor i1 %".118", -1
  %".120" = xor i8 %".104", %".115"
  %".121" = xor i8 %".104", %".106"
  %".122" = xor i8 %".121", 255
  %".123" = and i8 %".120", %".122"
  %".124" = xor i8 %".104", %".123"
  %".125" = xor i8 %".124", %".115"
  %".126" = xor i8 %".125", %".106"
  %".127" = lshr i8 %".126", 7
  %".128" = and i8 %".127", 1
  %".129" = trunc i8 %".128" to i1
  %".130" = lshr i8 %".123", 7
  %".131" = and i8 %".130", 1
  %".132" = trunc i8 %".131" to i1
  %".133" = xor i8 %".104", %".115"
  %".134" = xor i8 %".133", %".106"
  %".135" = lshr i8 %".134", 4
  %".136" = and i8 %".135", 1
  %".137" = trunc i8 %".136" to i1
  %".138" = inttoptr i32 %"EAX.2" to i8*
  store i8 %".115", i8* %".138"
  store i1 %".111", i1* %"zf"
  store i1 %".114", i1* %"nf"
  store i1 %".119", i1* %"pf"
  store i1 %".129", i1* %"cf"
  store i1 %".132", i1* %"of"
  store i1 %".137", i1* %"af"
  %"EAX.3" = load i32, i32* %"EAX"
  %".146" = mul i32 %"EAX.3", 2
  %".147" = inttoptr i32 %".146" to i8*
  %".148" = load i8, i8* %".147"
  %".149" = and i32 %"EAX.3", 255
  %".150" = trunc i32 %".149" to i8
  %".151" = sub i8 0, %".150"
  %".152" = sub i8 0, %".151"
  %".153" = add i8 %".148", %".152"
  %".154" = icmp ne i8 %".153", 0
  %".155" = select i1 %".154", i1 0, i1 1
  %".156" = lshr i8 %".153", 7
  %".157" = and i8 %".156", 1
  %".158" = trunc i8 %".157" to i1
  %".159" = add i8 %".148", %".150"
  %".160" = and i8 %".159", 255
  %".161" = call i8 @"llvm.ctpop.i8"(i8 %".160")
  %".162" = trunc i8 %".161" to i1
  %".163" = xor i1 %".162", -1
  %".164" = xor i8 %".148", %".159"
  %".165" = xor i8 %".148", %".150"
  %".166" = xor i8 %".165", 255
  %".167" = and i8 %".164", %".166"
  %".168" = xor i8 %".148", %".167"
  %".169" = xor i8 %".168", %".159"
  %".170" = xor i8 %".169", %".150"
  %".171" = lshr i8 %".170", 7
  %".172" = and i8 %".171", 1
  %".173" = trunc i8 %".172" to i1
  %".174" = lshr i8 %".167", 7
  %".175" = and i8 %".174", 1
  %".176" = trunc i8 %".175" to i1
  %".177" = xor i8 %".148", %".159"
  %".178" = xor i8 %".177", %".150"
  %".179" = lshr i8 %".178", 4
  %".180" = and i8 %".179", 1
  %".181" = trunc i8 %".180" to i1
  %".182" = inttoptr i32 %".146" to i8*
  store i8 %".159", i8* %".182"
  store i1 %".155", i1* %"zf"
  store i1 %".158", i1* %"nf"
  store i1 %".163", i1* %"pf"
  store i1 %".173", i1* %"cf"
  store i1 %".176", i1* %"of"
  store i1 %".181", i1* %"af"
  %"EAX.4" = load i32, i32* %"EAX"
  %".190" = inttoptr i32 %"EAX.4" to i8*
  %".191" = load i8, i8* %".190"
  %".192" = and i32 %"EAX.4", 255
  %".193" = trunc i32 %".192" to i8
  %".194" = sub i8 0, %".193"
  %".195" = sub i8 0, %".194"
  %".196" = add i8 %".191", %".195"
  %".197" = icmp ne i8 %".196", 0
  %".198" = select i1 %".197", i1 0, i1 1
  %".199" = lshr i8 %".196", 7
  %".200" = and i8 %".199", 1
  %".201" = trunc i8 %".200" to i1
  %".202" = add i8 %".191", %".193"
  %".203" = and i8 %".202", 255
  %".204" = call i8 @"llvm.ctpop.i8"(i8 %".203")
  %".205" = trunc i8 %".204" to i1
  %".206" = xor i1 %".205", -1
  %".207" = xor i8 %".191", %".202"
  %".208" = xor i8 %".191", %".193"
  %".209" = xor i8 %".208", 255
  %".210" = and i8 %".207", %".209"
  %".211" = xor i8 %".191", %".210"
  %".212" = xor i8 %".211", %".202"
  %".213" = xor i8 %".212", %".193"
  %".214" = lshr i8 %".213", 7
  %".215" = and i8 %".214", 1
  %".216" = trunc i8 %".215" to i1
  %".217" = lshr i8 %".210", 7
  %".218" = and i8 %".217", 1
  %".219" = trunc i8 %".218" to i1
  %".220" = xor i8 %".191", %".202"
  %".221" = xor i8 %".220", %".193"
  %".222" = lshr i8 %".221", 4
  %".223" = and i8 %".222", 1
  %".224" = trunc i8 %".223" to i1
  %".225" = inttoptr i32 %"EAX.4" to i8*
  store i8 %".202", i8* %".225"
  store i1 %".198", i1* %"zf"
  store i1 %".201", i1* %"nf"
  store i1 %".206", i1* %"pf"
  store i1 %".216", i1* %"cf"
  store i1 %".219", i1* %"of"
  store i1 %".224", i1* %"af"
  br label %"loc_key_1"
loc_key_1:
  store i32 0, i32* @"IRDst"
  br label %"exit"
}

@"IRDst" = global i32 0
@"pf" = global i1 0
@"af" = global i1 0
@"ESP" = global i32 0
@"EAX" = global i32 0
@"nf" = global i1 0
@"EBX" = global i32 0
@"EBP" = global i32 0
@"zf" = global i1 0
@"of" = global i1 0
@"EDX" = global i32 0
@"cf" = global i1 0