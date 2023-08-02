
startX=1
base="0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
random=1
#echo -e "$startX\n$base\n$random"|./main.sh

nohup echo -e "$startX\n$base\n$random"|./main.sh >> log 2>&1 &
