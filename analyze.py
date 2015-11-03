import pygraphviz as pgv
import sys, os, shutil
import multiprocessing
import itertools

from detector import displayGadget, GadgetType, GadgetClass, fetchInstruction, getPattern

seenPattern = {}
cnt = 0

rGadgetType = {}
rGadgetClass = {}

class GadgetDB:
	def __init__(self):
		self.gadgetStore = {}
		self.gadgetCount = 0

	def getId(self,gadgetPattern):
		item = self.gadgetStore.get(gadgetPattern,None)

		if item is None:
			return -1
		else:
			return item["id"]

	def add(self,gadgetPattern,classification):
		item = self.gadgetStore.get(gadgetPattern,None)
		if item is not None:
			item["count"] += 1
			return 0
		else:
			self.gadgetCount += 1
			newID = self.gadgetCount
			self.gadgetStore[gadgetPattern] = {"id":newID,"classification":classification,"count":1}
			#print "Added asdf"
			return newID

	def export(self,dstFolder):
		import csv
		with open(os.path.join(dstFolder,"analysis.csv"),"w") as f:
			fieldnames = ["id", "gadgetType", "gadgetClass" , "count", "pattern"]

			writer = csv.DictWriter(f,fieldnames=fieldnames,extrasaction='ignore')
			writer.writeheader()
			for k,v in self.gadgetStore.iteritems():
				v["gadgetType"] = rGadgetType[v["classification"][0]]
				v["gadgetClass"] = rGadgetClass[v["classification"][1]]
				v["pattern"] = k
				writer.writerow(v)

def process(flowfile, db,printInsn = True, insnFP=None, inspect=False,):
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

		for gadget, gclass, rootinsn, leafinsn in gadgets:
			pat = getPattern(gadget)
			gid = gdb.add(pat,gclass)
			if not gid == 0:
				print "gid",gid
				dstFolder = os.path.join(dfolder,"analysis")
				if not os.path.exists(dstFolder):
					os.makedirs(dstFolder)
				dstFolder = os.path.join(dstFolder,str(gid)+".png")
				#print dstFolder
				gadget.draw(dstFolder, "png", "dot")
			# g.draw("a.png","png","dot")
				#print rGadgetType[gclass[0]],rGadgetClass[gclass[1]]
				#print ""
				#print pat
				#print "Press enter to load next gadget"
				#raw_input()
			if printInsn:
				gid = gdb.getId(pat)
				insnFP.write("{0} {1}\n".format(gid,fetchInstruction(gadget)))


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

		# if not numGadget:
		# 	if moveNChosen:
		# 		dstFolder = os.path.join(dfolder, "fail")
		# 		if not os.path.exists(dstFolder):
		# 			os.makedirs(dstFolder)
		# 		shutil.move(flowfile, dstFolder)
		# 	return 0
		# else:
		# 	if moveNChosen:
		# 		dstFolder = os.path.join(dfolder, "pass")
		# 		if not os.path.exists(dstFolder):
		# 			os.makedirs(dstFolder)
		# 		shutil.move(flowfile, dstFolder)


		#g = pgv.AGraph(flowfile)
		#print flowfile.rsplit("/")[-1].rsplit("\\")[-1], numGadget, len([ga for ga in g.nodes() if ga.attr["shape"] == "box"]), [len([ga for gb in ga[0].nodes() if gb.attr["shape"] == "box"]) for ga in gadgets]

		
		#print "Done processing flow <Enter> for next flow"
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



	t = vars(GadgetClass)
	for key in t.keys():
		if t[key] is not None:
			rGadgetClass[t[key]] = key

	t = vars(GadgetType)
	for key in t.keys():
		if t[key] is not None:
			rGadgetType[t[key]] = key

	lp = 0
	totalNumGadgets = 0
	dfolder = sys.argv[1]
	q = []
	gdb = GadgetDB()


	dstFolder = os.path.join(dfolder,"analysis")
	if not os.path.exists(dstFolder):
		os.makedirs(dstFolder)
	insnFP = open(os.path.join(dfolder,"analysis","insn.txt"),"w")
	for i in os.listdir(dfolder):
		if i.startswith("flow"):
			# print i
			flowfile = os.path.join(dfolder, i)
			try:
				totalNumGadgets += process(flowfile,  gdb,printInsn = True,insnFP=insnFP,inspect=False)
			except Exception, e:
				print "errerr", i
				print e
				import traceback
				traceback.print_exc()

	insnFP.close()
	gdb.export(os.path.join(dfolder,"analysis"))
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
