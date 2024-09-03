set hon 6
set ser 13
set rou 1.66
set p 0.50
set simu_start 0.0
set sim_duration 10.0
set afa 100
set fai 2
set q [format "%.4f" [expr double($hon)/($hon+$ser)]]
set bta 5
set v 80
set flag 0
set flag1 0
set flag2 0
set band $hon
set at [expr ($ser*0.2+$hon*0.8*$p)]
set se [expr $q+$rou]
set ns [new Simulator]

$ns color 1 BLUE
$ns color 2 RED
$ns color 3 GREEN
$ns color 4 YELLOW

set nd [open out.tr w]
$ns trace-all $nd

proc finish {} {
   global ns nd
   $ns flush-trace
   close $nd
   exit 0
}

puts "\n"
puts "if判断条件如下:"

proc provider {f} {
   global afa p fai
   puts "(1-(1+fai)*p)*afa: [expr (1-(1+$fai)*$p)*$afa], (p-1)*afa: [expr ($p-1)*$afa]"
   if {[expr (1-(1+$fai)*$p)*$afa]>[expr ($p-1)*$afa]} { 
   return [expr $f+1]
   } else {
     return [expr $f-1]
   }
}

proc receiver_client {f} {
   global q
   puts "1-2.0*q: [expr 1-2.0*$q]"
   if {[expr 1-2.0*$q]>0} {     
      return [expr $f+1]
   } else {
      return [expr $f-1]
   }
}

proc receiver_attacker {f} {
    global afa fai bta rou v q
    puts "fai*afa-bta-(rou*v+fai*afa)*q: [expr $fai*$afa-$bta-($rou*$v+$fai*$afa)*$q]"
    if {[expr $fai*$afa-$bta-($rou*$v+$fai*$afa)*$q]>0} {    
       return [expr $f+1]
    } else {
       return [expr $f-1]
    }
}

set flag [provider $flag]
set flag1 [receiver_client $flag1]
set flag2 [receiver_attacker $flag2]
puts "\nq: $q\n"
puts "flag: $flag"
puts "flag1: $flag1"
puts "flag2: $flag2\n"

remove-all-packet-headers
add-packet-header IP Message
add-packet-header Flags IP TCP

for {set i 0} {$i<$hon+$ser+4} {incr i} {
 set n($i) [$ns node]
}

for {set i 0} {$i<$ser} {incr i} {
 $ns duplex-link $n($i) $n([expr $ser+$hon]) 1Mb 10ms DropTail 
 $ns queue-limit $n($i) $n([expr $ser+$hon]) 10
}

for {set i $ser} {$i<[expr $ser+$hon]} {incr i} {
 $ns duplex-link $n($i) $n([expr $ser+$hon]) [expr $band]Mb 10ms DropTail
 $ns queue-limit $n($i) $n([expr $ser+$hon]) 10
}

$ns duplex-link $n([expr $ser+$hon+1]) $n([expr $ser+$hon]) [expr $band]Mb 10ms DropTail
$ns queue-limit $n([expr $ser+$hon+1]) $n([expr $ser+$hon]) 10
$ns duplex-link $n([expr $ser+$hon+2]) $n([expr $ser+$hon+1]) [expr $band]Mb 10ms DropTail
$ns queue-limit $n([expr $ser+$hon+2]) $n([expr $ser+$hon+1]) 10
$ns duplex-link $n([expr $ser+$hon+3]) $n([expr $ser+$hon+1]) [expr $band]Mb 10ms DropTail
$ns queue-limit $n([expr $ser+$hon+3]) $n([expr $ser+$hon+1]) 10

for {set i 0} {$i<[expr $ser+$hon]} {incr i} {
 set null($i) [new Agent/Null]
 $ns attach-agent $n([expr $ser+$hon+2]) $null($i)
 set null([expr 100+$i]) [new Agent/Null]
 $ns attach-agent $n([expr $ser+$hon+3]) $null([expr 100+$i])
}

for {set i 0} {$i<$ser} {incr i} {
 set tcp([expr 20+$i]) [new Agent/TCP]
 $ns attach-agent $n([expr $ser+$hon+2]) $tcp([expr 20+$i])
 set ftp([expr 20+$i]) [new Application/FTP]
 $ftp([expr 20+$i]) attach-agent $tcp([expr 20+$i])
 $ftp([expr 20+$i]) set type_ FTP

 set udp([expr 40+$i]) [new Agent/UDP]
 $ns attach-agent $n([expr $ser+$hon+3]) $udp([expr 40+$i])
 set cbr([expr 40+$i]) [new Application/Traffic/CBR]
 $cbr([expr 40+$i]) attach-agent $udp([expr 40+$i])
 $cbr([expr 40+$i]) set type_ CBR
 $cbr([expr 40+$i]) set packet_size_ 1000
 $cbr([expr 40+$i]) set rate_ [expr $at]mb
 $cbr([expr 40+$i]) set random_ false
}

for {set i [expr $ser]} {$i<[expr $ser+$hon]} {incr i} {
 set tcp([expr 20+$i]) [new Agent/TCP]
 $ns attach-agent $n([expr $ser+$hon+2]) $tcp([expr 20+$i])
 set ftp([expr 20+$i]) [new Application/FTP]
 $ftp([expr 20+$i]) attach-agent $tcp([expr 20+$i])
 $ftp([expr 20+$i]) set type_ FTP

 set udp([expr 40+$i]) [new Agent/UDP]
 $ns attach-agent $n([expr $ser+$hon+3]) $udp([expr 40+$i])
 set cbr([expr 40+$i]) [new Application/Traffic/CBR]
 $cbr([expr 40+$i]) attach-agent $udp([expr 40+$i])
 $cbr([expr 40+$i]) set type_ CBR
 $cbr([expr 40+$i]) set packet_size_ 950
 $cbr([expr 40+$i]) set rate_ [expr $at]mb
 $cbr([expr 40+$i]) set random_ false
}

for {set i 0} {$i<$ser} {incr i} {
 $tcp([expr 20+$i]) set fid_ 3
 $udp([expr 40+$i]) set fid_ 4
}
for {set i [expr $ser]} {$i<[expr $ser+$hon]} {incr i} {
 $tcp([expr 20+$i]) set fid_ 3
 $udp([expr 40+$i]) set fid_ 4
}

$n([expr $ser+$hon+2]) color "GREEN"
$n([expr $ser+$hon+3]) color "YELLOW"

for {set i 0} {$i<$ser} {incr i} {
 $n($i) color "BLUE"
 set udp($i) [new Agent/UDP]
 $ns attach-agent $n($i) $udp($i)
 $ns connect $udp($i) $null($i)
 $udp($i) set fid_ 1
 set cbr($i) [new Application/Traffic/CBR]
 $cbr($i) attach-agent $udp($i)
 $cbr($i) set type_ CBR
 $cbr($i) set packet_size_ 500
 $cbr($i) set rate_ [expr $se]mb
 $cbr($i) set random_ false
 set udp([expr 100+$i]) [new Agent/UDP]
 $ns attach-agent $n($i) $udp([expr 100+$i])
 $ns connect $udp([expr 100+$i]) $null([expr 100+$i])
 $udp([expr 100+$i]) set fid_ 1
 set cbr([expr 100+$i]) [new Application/Traffic/CBR]
 $cbr([expr 100+$i]) attach-agent $udp([expr 100+$i])
 $cbr([expr 100+$i]) set type_ CBR
 $cbr([expr 100+$i]) set packet_size_ 600
 $cbr([expr 100+$i]) set rate_ [expr $se]mb
 $cbr([expr 100+$i]) set random_ false
 set sink([expr 20+$i]) [new Agent/TCPSink]
 $ns attach-agent $n($i) $sink([expr 20+$i])
 set null([expr 40+$i]) [new Agent/Null]
 $ns attach-agent $n($i) $null([expr 40+$i])
 $ns connect $tcp([expr 20+$i]) $sink([expr 20+$i])
 $ns connect $udp([expr 40+$i]) $null([expr 40+$i])
}

for {set i [expr $ser]} {$i<[expr $ser+$hon]} {incr i} {
 $n($i) color "RED"
 set udp([expr 100+$i]) [new Agent/UDP]
 $ns attach-agent $n($i) $udp([expr 100+$i])
 $ns connect $udp([expr 100+$i]) $null([expr 100+$i])
 $udp([expr 100+$i]) set fid_ 2
 set cbr([expr 100+$i]) [new Application/Traffic/CBR]
 $cbr([expr 100+$i]) attach-agent $udp([expr 100+$i])
 $cbr([expr 100+$i]) set type_ CBR
 $cbr([expr 100+$i]) set packet_size_ 800
 $cbr([expr 100+$i]) set rate_ [expr $at]mb
 $cbr([expr 100+$i]) set random_ false
 set sink([expr 20+$i]) [new Agent/TCPSink]
 $ns attach-agent $n($i) $sink([expr 20+$i])
 set null([expr 40+$i]) [new Agent/Null]
 $ns attach-agent $n($i) $null([expr 40+$i])
 $ns connect $tcp([expr 20+$i]) $sink([expr 20+$i])
 $ns connect $udp([expr 40+$i]) $null([expr 40+$i])
}

puts "flag: $flag"
puts "flag1: $flag1"
puts "flag2: $flag2\n"

for {set i 0} {$i<$ser} {incr i} {
 if {$flag>0} {
   $ns at $simu_start "$cbr($i) start"
   $ns at [expr $sim_duration] "$cbr($i) stop"
   $ns at $simu_start "$cbr([expr 100+$i]) start"
   $ns at [expr $sim_duration] "$cbr([expr 100+$i]) stop"
 }
}
for {set i [expr $ser]} {$i<[expr $ser+$hon]} {incr i} {
 $ns at $simu_start "$cbr([expr 100+$i]) start"
 set now [$ns now]
 $ns at [expr $sim_duration] "$cbr([expr 100+$i]) stop"
}

for {set i 0} {$i<$ser} {incr i} {
   if {$flag1>0} {
    $ns at $simu_start "$ftp([expr 20+$i]) start"
    $ns at [expr $sim_duration-1] "$ftp([expr 20+$i]) stop"
   }
   if {$flag2>0} {
    $ns at $simu_start "$cbr([expr 40+$i]) start"
    $ns at [expr $sim_duration-1] "$cbr([expr 40+$i]) stop"
   }
}
for {set i [expr $ser]} {$i<[expr $ser+$hon]} {incr i} {
  if {$flag1>0} {
    $ns at $simu_start "$ftp([expr 20+$i]) start"
    $ns at [expr $sim_duration-1] "$ftp([expr 20+$i]) stop"
  }
  if {$flag2>0} {
    $ns at $simu_start "$cbr([expr 40+$i]) start"
    $ns at [expr $sim_duration-1] "$cbr([expr 40+$i]) stop"
  }
}

$ns at $sim_duration "finish"

$ns run

