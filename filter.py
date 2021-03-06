import pygraphviz as pgv
import sys, os, shutil
import multiprocessing
import itertools

from detector import displayGadget, fetchInstruction, getPattern
from classify import GadgetClass,GadgetType

seenPattern = {}
cnt = 0
def process(flowfile, moveNChosen=False, dfolder="", moveFolder="NoGadget", inspect=False):
	# print flowfile
	global cnt
	global seenPattern

	cnt += 1
	if not cnt % 1000:
		print cnt, flowfile
	# print len(g.edges()),g.edges()
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

	# g = pgv.AGraph(flowfile)

	# num_edge = len(g.edges())

	# if num_edge<2: #implies to register
	# 	return 0


	# if num_edge == 2 and all(("EIP" in e[0] or "EIP" in e[1]) for e in g.iteredges()): #skip jne/je/jz
	# 	return 0


		# memCnt = 0
		# for vtx in g.iternodes():
		# 	if vtx.name.startswith("mem_"):
		# 		memCnt += 1

		# if memCnt < 1:
		# 	return 0


		# raw_input()
	try:
		numGadget, gadgets = displayGadget(flowfile, "b.png", min_instr=0, min_mem_in=0, count=False, inspect=False)
		if inspect and numGadget:
			if any((GadgetType.Unknown, GadgetClass.Unknown) == gclass for _, gclass, _, _ in gadgets):
				g.draw("a.png", "png", "dot")
			for gadget, gclass, rootinsn, leafinsn in gadgets:
				print rootinsn, leafinsn
				if gclass == (GadgetType.Unknown, GadgetClass.Unknown):
				# if 1==1:


					pat = getPattern(gadget)
					seenPattern[pat] = seenPattern.get(pat, 0) + 1
					if seenPattern.get(pat, 0) == 1:
						gadget.draw("b.png", "png", "dot")
						# g.draw("a.png","png","dot")
						print fetchInstruction(gadget)
						print ""
						print pat
						print "Press enter to load next gadget"
						raw_input()
				else:
					print "known"

		if not numGadget:
			if moveNChosen:
				dstFolder = os.path.join(dfolder, "fail")
				if not os.path.exists(dstFolder):
					os.makedirs(dstFolder)
				shutil.move(flowfile, dstFolder)
			return 0
		else:
			if moveNChosen:
				dstFolder = os.path.join(dfolder, "pass")
				if not os.path.exists(dstFolder):
					os.makedirs(dstFolder)
				shutil.move(flowfile, dstFolder)


		if inspect:
			print flowfile.rsplit("/")[-1].rsplit("\\")[-1], numGadget, len([ga for ga in g.nodes() if ga.attr["shape"] == "box"]), [len([ga for gb in ga[0].nodes() if gb.attr["shape"] == "box"]) for ga in gadgets]

		if inspect:
			print "Done processing flow <Enter> for next flow"
			# raw_input()
		return numGadget
	except Exception, e:
		print "errerr", flowfile
		print e
		import traceback
		traceback.print_exc()
		# raise Exception()
		errFolder = os.path.join(dfolder, "error")
		if not os.path.exists(errFolder):
			os.makedirs(errFolder)
		shutil.move(flowfile, errFolder)
		print "file moved to", errFolder


def process_star(inpt):
	# print
	inpt = (inpt[0],) + inpt[1]
	return process(*inpt)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.exit("a.py <dotfile>")


	moveNChosen = True
	moveFolder = "NoGadget"
	inspect = False


	lp = 0
	totalNumGadgets = 0
	dfolder = sys.argv[1]
	q = []
	for i in os.listdir(dfolder):
		if i.startswith("flow"):
			# print i
			flowfile = os.path.join(dfolder, i)
			try:
				totalNumGadgets += process(flowfile, moveNChosen, dfolder, moveFolder, inspect)
			except Exception, e:
				print "errerr", i
				print e
				import traceback
				traceback.print_exc()



			# q.append(flowfile)

	# pool = multiprocessing.Pool(1)
	# #http://stackoverflow.com/a/28463266

	# for k in itertools.izip(q, itertools.repeat((str(moveNChosen),dfolder,moveFolder))):
	# #	print k
	# result = pool.map(process_star,itertools.izip(q, itertools.repeat((moveNChosen,dfolder,moveFolder,inspect))))
	# pool.close()
	# pool.join()

	# totalNumGadgets = sum(result)
	print "totalNumGadgets", totalNumGadgets
