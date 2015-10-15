import pygraphviz as pgv
import sys

# dfile = "small_flows/flow51005"


def fetchInstruction(g):
	ret = []
	for i in g.iternodes():
		if not i.startswith("R_"):  # # For bug in sliceall where some register is box
			if i.attr["shape"] == "box":
				ret.append(i.attr["label"])
	return ret

def getPattern(g):
	insns = fetchInstruction(g)
	ret = []
	for insn in insns:
		# [xxxx] 0x1234: movl xyz xyu
		try:
			insn = insn.split(" ", 3)
			ret.append(insn[2])
		except:
			print insns
			print g
			# print g.draw("err.png","png","dot")
			raise Exception("Unable to find pattern for ")
	return tuple(ret)

def getAddrs(g):
	insns = fetchInstruction(g)
	ret = []
	for insn in insns:
		# [xxxx] 0x1234: movl xyz xyu
		try:
			insn = insn.split(" ", 3)
			ret.append(int(insn[1][2:-1],16))
		except:
			print insns
			print g
			# print g.draw("err.png","png","dot")
			raise Exception("Unable to find addr for ")
	return tuple(ret)

class GadgetType:
	Movement, Calculation, Setter, Unknown = range(4)
class GadgetClass:
	Basic, NonBasic, Constant, Conditional , Unclassified, Unknown = range(6)

def classifier(gadget):

	pattern = getPattern(gadget)
	instructions = fetchInstruction(gadget)

	# basic setter detect movl xxx (eax) -> mem
	if pattern == ('movl',):
		return (GadgetType.Setter, GadgetClass.Constant)

	if pattern == ('movb',):
		return (GadgetType.Setter, GadgetClass.Constant)

	# basic adder addl xxx (eax) -> mem
	if pattern in [('addl',), ('subl',)]:
		return (GadgetType.Calculation, GadgetClass.Constant)

	# mov 0x1234 eax -> eax -> movl eax, (ebx) -> mem
	if pattern == ('movl','mov'):
		return (GadgetType.Setter, GadgetClass.Constant)

	# detect basic movement mem -> insn -> reg -> insn -> mem
	if pattern == ('movl', 'movl'):
		return (GadgetType.Movement, GadgetClass.Basic)

	# basic adder  mem -> movl -> reg -> add xxx reg -> reg -> movl -> mem
	if pattern in [
		('movl', 'add', 'movl'),
		(u'movl', u'and', u'movl'),
		('movl','imull'),(u'movl', u'addl')
										]:
		return (GadgetType.Calculation, GadgetClass.Basic)

	# mem -> subl -> reg -> addl -> mem
	if pattern in [
		(u'addl', u'subl') ,
		(u'adcl', u'sbbl')
										]:
		return (GadgetType.Calculation, GadgetClass.NonBasic)

	if pattern == ('movl', 'cmovz', 'mov'):
		return (GadgetType.Movement, GadgetClass.Conditional)

	if pattern == (u'movl', u'xor'):
		return (GadgetType.Setter, GadgetClass.Constant)

	# unclassified = [
	# 	(u'movl', u'cmovz'),
	# 	(u'movl', u'or', u'movzx', u'or', u'setz', u'setz', u'add', u'setz'),
	# 	(u'movl', u'lea', u'add', u'movl'),
	# 	(u'movw', u'movzxw'),
	# 	(u'movl', u'sub', u'xor'),
	# 	(u'movsbb',),
	# 	(u'movsww',),
	# 	(u'andb',),
	# 	(u'movl', u'lea'),
	# 	(u'movl', u'mov', u'mov', u'xor'),
	# 	(u'movl', u'and', u'lea', u'sub', u'and', u'lea', u'lea', u'movl', u'sub'),
	# 	(u'movl', u'lea', u'and', u'lea', u'sub', u'and', u'lea', u'lea', u'movl', u'sub'),
	# 	(u'movl', u'add', u'and', u'lea', u'sub', u'and', u'lea', u'lea', u'movl', u'sub', u'xor'),
	# 	(u'movl', u'rdtsc'), (u'movl', u'setz'), (u'movl', u'mov', u'xor'),(u'movl', u'cmovnz'),(u'movb', u'or', u'and', u'movzxb', u'and', u'movzxb'),
	# 	(u'movb', u'or', u'and', u'movzxb'),
	# 	(u'movl', u'cmovnz', u'movzx', u'and', u'movzxb'),(u'movl', u'cmovz', u'mov')


	# ]

	# if pattern in unclassified:
	# 	return (GadgetType.Movement,GadgetClass.Unclassified)

	return (GadgetType.Unknown, GadgetClass.Unknown)

def displayGadget(dfile, output="b.png", min_instr=0, min_mem_in=0, count=False, inspect=False):
	g = pgv.AGraph(dfile)


	visited = {}
	stack = []
	queue = []
	# Look for all tail node
	numGadget = 0
	gadgets = []
	for data_vtx in g.in_edges_iter():
		gadget = pgv.AGraph(directed=True, strict=False)
		gadget.node_attr.update(shape="box")
		# gadgetcol = []

		parent = data_vtx[0]
		child = data_vtx[1]

		if not child.startswith("mem_"):
			continue

		if visited.get(parent, False):
			continue

		visited[parent] = True

		# if g.in_degree(parent) == 0 or not g.in_edges(parent)[0][0].startswith("R"):
			# continue

		# print data_vtx
		# gadgetcol.append(data_vtx)

		t_parent_node = g.get_node(parent)
		t_child_node = g.get_node(child)
		gadget.add_node(t_parent_node.name, **t_parent_node.attr)
		gadget.add_node(t_child_node.name, **t_child_node.attr)
		gadget.add_edge(parent, child, None, **data_vtx.attr)

		# Traverse up to split
		hasMemInPreRead = False
		rootinsn = [[t_parent_node, t_parent_node]]
		leafinsn = t_parent_node
		while g.in_degree(parent) == 1:
			rootinsn = None
			parent_edge = g.in_edges(parent)[0]
			parent = parent_edge[0]

			t_parent_node = g.get_node(parent)
			gadget.add_node(t_parent_node.name, **t_parent_node.attr)
			gadget.add_edge(parent_edge[0], parent_edge[1], None, **parent_edge.attr)
			# gadgetcol.append(parent_edge)

			# print "pr",parent
			if parent.startswith("mem_"):
				hasMemInPreRead = True
				if g.in_degree(parent) != 0:
					rootinsn = [ [g.get_node(g.in_edges(parent)[0][0]), g.get_node(parent_edge[1]) ]]
				else:
					rootinsn = [[g.get_node(parent_edge[0]), g.get_node(parent_edge[1])]]



				# print "mem in pr"
				break

			# gadget.add_edge(parent_edge)

		if rootinsn is None:
			if g.in_degree(parent) == 0:
				t_parent_node = g.get_node(parent)
				rootinsn = [[t_parent_node, t_parent_node]]
			else:
				rootinsn = []

		# print gadget



		# print parent,child
		# print "gc",gadgetcol
		# continue
		# at the point where we have input from 2 memory loc
		def followToMemLoad(edge, g, gadget):
			parent = edge[0]
			child = edge[1]
			t_parent_node = g.get_node(parent)
			c_node = g.get_node(child)
			gadget.add_node(t_parent_node.name, **t_parent_node.attr)
			gadget.add_edge(parent, child, None, **edge.attr)


			# print parent,child
			# print "pear"
			if parent.startswith("mem_"):
				hasRegOp = False
				for edge2 in g.in_edges_iter(child):
					if not edge2[0].startswith("mem_"):
						hasRegOp = True
						# print "asdsad",edge2
						break
				if hasRegOp:
					t_node = g.get_node(edge2[0])

					gadget.add_node(t_node.name, **t_node.attr)
					gadget.add_edge(edge2[0], child, None, **edge.attr)
					if g.in_degree(parent) != 0:
			 			return -1, [[g.get_node(g.in_edges(parent)[0][0]), c_node], [t_node, c_node]]
			 		else:
			 			return -1, [[c_node, c_node], [t_node, c_node]]
				# print g.in_edges(parent)[0]

				if g.in_degree(parent) != 0:
					return -1, [[g.get_node(g.in_edges(parent)[0][0]), c_node]]
				else:
					return -1, [[c_node, c_node]]


			# print "apple"
			# noMemLoad = 0
			rval = 0
			parentCnt = 0
			rootinsn = []
			visited2 = {}
			for edge in g.in_edges_iter(parent):

				if visited2.get(edge[0], False):
					continue

				visited2[edge[0]] = True

				# $print edge
				arval, insn = followToMemLoad(edge, g, gadget)
				if arval == -1:
					return 0, insn
				rval += arval
				parentCnt += 1
				rootinsn += insn


			if parentCnt == 0:
				return 1, [[t_parent_node, t_parent_node]]
			return rval, rootinsn  # if not len(rootinsn) == 1 else rootinsn[0]


		if not hasMemInPreRead:
			# rootinsn = []
			forkHasNoMemLoad = 1
			for fork_edge in g.in_edges_iter(parent):
				forkHasNoMemLoad, rinsn = followToMemLoad(fork_edge, g, gadget)
				rootinsn += rinsn
				# print forkHasNoMemLoad
				if forkHasNoMemLoad == -1:
					# rootinsn += rinsn
					break
				# rootinsn += rinsn
					# raise Exception("get -1")
					# hasRegOp = False
					# for edge in g.in_edges_iter(parent):
					#  	if not edge[0].startswith("mem_"):
					#  		hasRegOp = True
					# 		# break

					# if hasRegOp:
						# forkHasNoMemLoad = 1
					# break
				# if forkHasNoMemLoad > 0: break

			# if forkHasNoMemLoad >0 : continue

		# #filtering

		min_addr = int("8048000",16)
		max_addr = int("805c86b",16)

		if not any((min_addr <= instr_addr and instr_addr <= max_addr) for instr_addr in getAddrs(gadget)):
			continue

		RegInFilter = ["R_ESP_0_pre"]
		if len(rootinsn) == 1 and rootinsn[0][0] in RegInFilter:
			continue

		LastInsnFilter = ["push"]
		if any(f in leafinsn.attr["label"] for f in LastInsnFilter):
			continue

		FirstInsnFilter = ["popl"]
		# print len(rootinsn)
		# print (rootinsn)
		if len(rootinsn) == 1 and any(f in rootinsn[0][1].attr["label"] for f in FirstInsnFilter):
			continue

		instructions = fetchInstruction(gadget)
		insnException = ["calll","%ebp","%esp","%eip"]
		if any(keyword in instruction for keyword in insnException for instruction in instructions):
			continue

		# print rootinsn,leafinsn

		if min_instr or min_mem_in or count:
			instrCnt = 0
			mem_in_cnt = 0
			for v in gadget.nodes():
				if (count or min_instr) and v.attr["shape"] == "box":
					instrCnt += 1
				if (count or min_mem_in) and gadget.in_degree(v) == 0:
					mem_in_cnt += 1

			if min_instr and instrCnt < min_instr:
				continue
			if min_mem_in and mem_in_cnt < min_mem_in:
				continue
			if count:
				print "instrCnt", instrCnt
				print "min_mem_in", min_mem_in

		numGadget += 1
		gclass = classifier(gadget)
		gadgets.append([gadget, gclass, rootinsn, leafinsn])

		if inspect:
			# if gclass == (GadgetType.Unknown,GadgetClass.Unknown):
			print "insn"
			print instructions
			print 			
			print "pattern"
			print getPattern(gadget)
			print 
			print "addrs"
			print getAddrs(gadget)
			print 
			print "rootinsn"
			print rootinsn
			print 
			print "leafinsn"
			print leafinsn
			gadget.draw(output, "png", "dot")
			print "Press enter to load next gadget"
			raw_input()
			# else:
			# 	print "class",gclass
	g.clear()
	return numGadget, gadgets

if __name__ == "__main__":
	if len(sys.argv) < 2:
		sys.exit("a.py <dotfile>")

	dfile = sys.argv[1]
	print displayGadget(dfile, inspect=True)
