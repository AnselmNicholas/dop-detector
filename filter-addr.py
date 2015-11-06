import sys,csv
from classify import classifier,GadgetClass,GadgetType
def getPattern(insns):
	ret = []
	for insn in insns:
		# [xxxx] 0x1234: movl xyz xyu
		try:
			insn = insn.split(" ", 3)
			ret.append(insn[2])
		except:
			print insns
			# print g.draw("err.png","png","dot")
			raise Exception("Unable to find pattern for ")
	return tuple(ret)


def filterAddr(ifile):
	seen = []
	counter = 0
	classCnt = {}
	with open(ifile,"r") as f:
		for line in f:
			gid, insns = line.strip().split(" ",1)
			insns = insns.split("u'")
			gidDaddr = gid + "-" + insns[1].split()[1]
			if not gidDaddr in seen:
				seen.append(gidDaddr)
				counter += 1

				classification = classifier(getPattern(insns[1:-1]))
				#print classification
				currClassCnt = classCnt.get(classification,0)
				classCnt[classification] = currClassCnt + 1


	return counter,classCnt


if __name__ == "__main__":
	if len(sys.argv) < 2:
		sys.exit("a.py <raw insn.txt>")
	
	counterA = []
	classCntA = []

	for i in range(1,len(sys.argv)):
		dfile = sys.argv[i]
		ctr, clsCtr = filterAddr(dfile)

		counterA.append(ctr)
		classCntA.append(clsCtr)

	print "seen", sum(counterA)

	classificationCnt = {}

	for clsCtr in classCntA:
		for keyT, valueT in GadgetType.__dict__.items():
			if not keyT.startswith("__"):
				for keyC, valueC in GadgetClass.__dict__.items():
					if not keyC.startswith("__"):
						cc = clsCtr.get((valueT,valueC),0)
						if not cc == 0:
							#print keyT,keyC, cc
							classification = (valueT,valueC)
							currClassCnt = classificationCnt.get(classification,0)
							classificationCnt[classification] = currClassCnt + 1

		for keyT, valueT in GadgetType.__dict__.items():
			if not keyT.startswith("__"):
				for keyC, valueC in GadgetClass.__dict__.items():
					if not keyC.startswith("__"):
						cc = clsCtr.get((valueT,valueC),0)
						if not cc == 0:
							print keyT,keyC, cc