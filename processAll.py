import pygraphviz as pgv
import sys,os,shutil
import multiprocessing
import itertools

from detector import displayGadget


def process(flowfile,moveNChosen=False,dfolder="",moveFolder = "NoGadget"):
	#print len(g.edges()),g.edges()
	# if len(g.edges()) < 3:
	# 	continue

	# memCnt = 0
	# for vtx in g.iternodes():
	# 	if vtx.name.startswith("mem_"):
	# 		memCnt += 1

	# if memCnt < 8:
	# 	continue



	# lp += 1
	# if not lp % 1000:
	# 	import gc
	# 	gc.collect()
	# 	import objgraph
	# 	print objgraph.show_most_common_types()
	# 	from guppy import hpy
	# 	h = hpy()
	# 	print h.heap()

	#g.draw("a.png","png","dot")
	numGadget,gadgets = displayGadget(flowfile,"b.png",min_instr=3,min_mem_in = 2, count = False,inspect=False)

	if not numGadget:
		if moveNChosen:
			dstFolder = os.path.join(dfolder,moveFolder)
			if not os.path.exists(dstFolder):
				os.makedirs(dstFolder)
			shutil.move(flowfile,dstFolder)
		return 0

	g = pgv.AGraph(flowfile)

	#print "Done processing flow <Enter> for next flow"
	
	print flowfile,numGadget, len([ga for ga in g.nodes() if ga.attr["shape"]=="box"]), [len([ga for gb in ga.nodes() if gb.attr["shape"]=="box"]) for ga in gadgets]
	return numGadget
	#raw_input()


def process_star(inpt):
	#print 
	inpt = (inpt[0],) + inpt[1]
	return process(*inpt)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.exit("a.py <dotfile>")
	

	moveNChosen = True
	moveFolder = "NoGadget"
	

	lp = 0
	totalNumGadgets = 0
	dfolder = sys.argv[1]
	q = []
	for i in os.listdir(dfolder):
		if i.startswith("flow"):
			#print i
			flowfile = os.path.join(dfolder,i)
			q.append(flowfile)

	pool = multiprocessing.Pool(200)
	#http://stackoverflow.com/a/28463266

	#for k in itertools.izip(q, itertools.repeat((str(moveNChosen),dfolder,moveFolder))):
	#	print k
	try:
		result = pool.map(process_star,itertools.izip(q, itertools.repeat((moveNChosen,dfolder,moveFolder))))
		pool.close()
		pool.join()
	except KeyboardInterrupt:
		pool.terminate()

	totalNumGadgets = sum(result)
	print "totalNumGadgets",totalNumGadgets
