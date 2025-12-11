# kAFL Status Plot (Professional Edition)
# Usage: gnuplot -c stats_v3.plot $workdir/stats.csv

indata1=ARG1

# 输出设置：更高分辨率，抗锯齿
set terminal wxt size 1200,1000 enhanced persist font "Segoe UI,10"
# set terminal pngcairo size 1200,1000 enhanced font "Segoe UI,10"
# set output 'kafl_analysis_v3.png'

set multiplot layout 3,1 title "kAFL Session Deep Dive" font ",16"

# === 全局美化 ===
set style fill transparent solid 0.3 noborder # 设置填充透明度
set grid xtics mxtics ytics linecolor rgb '#dddddd' linetype 1  # 主网格
set grid mytics linecolor rgb '#eeeeee' linetype 0             # 次网格
set border linecolor rgb '#666666'
set tics textcolor rgb '#333333'
set key outside right top font ",9"
set datafile separator ';'

# === X轴设置 (对数 + 次级刻度) ===
set logscale x
set mxtics 10  # 开启次级刻度 (10, 20, 30...)
set xlabel "Test Cases (Log Scale)"
set format x "10^{%L}" # 科学计数法显示 10^1, 10^2...

# === 图表 1: 吞吐量瓶颈分析 ===
set title "Throughput & Backlog Analysis"
set ylabel "Execs/s"	
set y2label "Favorites Count"
set yrange [0:*]
set y2range [0:*]
set ytics nomirror
set y2tics

# 优化层级：先画灰色的 Pending (背景)，再画红色的 Total，最后画蓝色的速度 (前景)
plot indata1 using 12:11 title 'Favs Pending (Backlog)' with filledcurve x1 linecolor rgb '#aaaaaa', \
     '' using 12:5 title 'Favs Total' with lines linecolor rgb '#cc0000' linewidth 2 axes x1y2, \
     '' using 12:2 title 'Execs/s' with lines linecolor rgb '#0075dc' linewidth 1.5

# === 图表 2: 覆盖率微观演进 ===
unset y2tics
unset y2label
set title "Coverage Evolution (Micro-view)"
set ylabel "Edges Count"

# 自动缩放 + 增加 buffer 空间，防止线条贴顶
set autoscale y
set offset graph 0, 0, 0.05, 0.05 

plot indata1 using 12:13 title 'Bitmap Edges' with steps linecolor rgb '#222222' linewidth 2

# === 图表 3: 异常发现 ===
set title "Findings Timeline"
set ylabel "Count"
unset logscale y
set yrange [-0.5:5] # 固定一个小的范围，如果有 crash 会很明显
set offset 0,0,0,0

plot indata1 using 12:6 title 'Crashes' with lines linecolor rgb '#9900cc' linewidth 3, \
     '' using 12:7 title 'kASan' with lines linecolor rgb '#009944' linewidth 3, \
     '' using 12:8 title 'Timeouts' with lines linecolor rgb '#ff8800' linewidth 2

unset multiplot
