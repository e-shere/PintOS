#!/bin/sh
for i in 1 2 3 4 5 7 8 9 0 1 2 3 4 5 6 7 8 9 0
do
  pintos -q run priority-preservation >> output.txt;
  #echo "JKKK"
  #cat output.txt;
  #echo "UHIU"
done
