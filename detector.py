import pygraphviz as pgv
import sys

#dfile = "small_flows/flow51005"
def displayGadget(dfile,output="a.png",min_instr = 0,min_mem_in = 0,count=False,inspect=False):
	g = pgv.AGraph(dfile)


	visited = {}
	stack = []
	queue = []
	#Look for all tail node
	numGadget = 0
	gadgets = []
	for data_vtx in g.in_edges_iter():
		gadget = pgv.AGraph(directed=True,strict=False)
		gadget.node_attr.update(shape="box")
		gadgetcol = []

		parent = data_vtx[0]
		child = data_vtx[1]
		if not child.startswith("mem_"):
			continue

		if visited.get(parent, False):
			continue

		visited[parent] = True

		if g.in_degree(parent) == 0 or not g.in_edges(parent)[0][0].startswith("R"):
			continue

		#print data_vtx
		gadgetcol.append(data_vtx)
		gadget.add_node(g.get_node(parent).name,**g.get_node(parent).attr)
		gadget.add_node(g.get_node(child).name,**g.get_node(child).attr)
		gadget.add_edge(parent,child,None,**data_vtx.attr)

		#Traverse up to split
		hasMemInPreRead = False
		while g.in_degree(parent) == 1:
			parent_edge = g.in_edges(parent)[0]
			parent = parent_edge[0]
			gadget.add_node(g.get_node(parent).name,**g.get_node(parent).attr)
			gadget.add_edge(parent_edge[0],parent_edge[1],None,**parent_edge.attr)
			gadgetcol.append(parent_edge)
			if parent.startswith("mem_"):
				hasMemInPreRead = True
				break
			#gadget.add_edge(parent_edge)
			


		

		#print parent,child
		#print "gc",gadgetcol
		#continue
		#at the point where we have input from 2 memory loc
		def followToMemLoad(edge,g,gadget):
			parent = edge[0]
			child = edge[1]

			gadget.add_node(g.get_node(parent).name,**g.get_node(parent).attr)
			gadget.add_edge(parent,child,None,**edge.attr)


			#print parent,child

			if parent.startswith("mem_"):
				hasRegOp = False
				for edge2 in g.in_edges_iter(child):
					if not edge2[0].startswith("mem_"):
						hasRegOp = True
						break
				if hasRegOp:
					return 1
				return -1

			#noMemLoad = 0
			rval = 0
			parentCnt = 0
			for edge in g.in_edges_iter(parent):
				#$print edge
				arval = followToMemLoad(edge,g,gadget)
				if arval == -1:
					return 0
				rval += arval
				parentCnt += 1

			
			if parentCnt == 0:
				return 1
			return rval

		if not hasMemInPreRead:
			forkHasNoMemLoad = 1
			for fork_edge in g.in_edges_iter(parent):
				forkHasNoMemLoad = followToMemLoad(fork_edge,g,gadget)
				#print forkHasNoMemLoad
				if forkHasNoMemLoad == -1:
					hasRegOp = False
					for edge in g.in_edges_iter(parent):
						if not edge[0].startswith("mem_"):
							hasRegOp = True
							break

					if hasRegOp:
						forkHasNoMemLoad = 1
					break
				if forkHasNoMemLoad > 0: break

			if forkHasNoMemLoad >0 : continue

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
				print "instrCnt",instrCnt
				print "min_mem_in",min_mem_in

		numGadget += 1
		gadgets.append(gadget)
		if inspect:
			gadget.draw(output,"png","dot")
			print "Press enter to load next gadget"
			raw_input()
	g.clear()
	g.close()
	g = None
	return numGadget,gadgets

if __name__ == "__main__":
	if len(sys.argv) < 2:
		sys.exit("a.py <dotfile>")

	dfile = sys.argv[1]
	displayGadget(dfile,inspect=True)