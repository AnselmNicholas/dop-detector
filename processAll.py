import pygraphviz as pgv
import sys,os,shutil

from detector import displayGadget

if len(sys.argv) < 2:
	sys.exit("a.py <dotfile>")

moveNChosen = True
moveFolder = "NoGadget"

lp = 0
totalNumGadgets = 0
dfolder = sys.argv[1]
for i in os.listdir(dfolder):
	if i.startswith("flow"):
		#print i
		flowfile = os.path.join(dfolder,i)
		
		#print len(g.edges()),g.edges()
		# if len(g.edges()) < 3:
		# 	continue

		# memCnt = 0
		# for vtx in g.iternodes():
		# 	if vtx.name.startswith("mem_"):
		# 		memCnt += 1

		# if memCnt < 8:
		# 	continue

		

		lp += 1
		if not lp % 1000:
			from guppy import hpy
			h = hpy()
			print h.heap()
		
		
		numGadget,gadgets = displayGadget(flowfile,"b.png",min_instr=3,min_mem_in = 2, count = False)
		
		if not numGadget:
			if moveNChosen:
				dstFolder = os.path.join(dfolder,moveFolder)
				if not os.path.exists(dstFolder):
					os.makedirs(dstFolder)
				shutil.move(flowfile,dstFolder)
			continue
		
		g = pgv.AGraph(flowfile)
		#g.draw("a.png","png","dot")
		#print "Done processing flow <Enter> for next flow"
		totalNumGadgets += numGadget
		print i,numGadget, len(g.nodes()), [len(ga.nodes()) for ga in gadgets]
		#raw_input()


print "totalNumGadgets",totalNumGadgets
