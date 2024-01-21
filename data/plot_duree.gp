datafile = 'duree.data'

set style data histograms
set key top left
set term png size 1280,720

set terminal pngcairo enhanced font 'Verdana,12'
set output 'histo_duree.png'
set title "Durée de l'attaque pour chaque hash"
set xlabel 'HASHs'
set ylabel 'Durée (s)'
set style data histograms
set style fill solid border rgb "black"

set boxwidth 0.5
set xtic rotate by -45 scale 0 font ",8"

plot for [i=2:5] datafile using i:xtic(1) title column(i)
