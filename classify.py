class GadgetType:
	Movement, Calculation, Setter, Unknown = range(4)
class GadgetClass:
	Basic, NonBasic, Constant, Conditional , Unclassified, Unknown = range(6)

def classifier(pattern):
	############
	# Movement #
	############

	# detect basic movement mem -> insn -> reg -> insn -> mem
	if pattern in [	('movl', 'movl'),
					(u'movl', u'xor'),
					(u'movl', u'movzx', u'setnz'),
					(u'movl', u'movzx', u'setz'),
					(u'movw', u'movzxw'),
					(u'movb', u'mov', u'movl'),
					(u'movl', u'mov', u'mov'),
					(u'movl', u'movzx', u'movzxw'),
					(u'movl', u'cwde', u'movzxw'),
					(u'movl', u'lea'),
					(u'movw', u'movl')
											]:
		return (GadgetType.Movement, GadgetClass.Basic)

	if pattern in [('movl', 'cmovz', 'mov')]:
		return (GadgetType.Movement, GadgetClass.Conditional)

	###############
	# Calculation #
	###############

	# basic adder  mem -> movl -> reg -> add xxx reg -> reg -> movl -> mem
	if pattern in [
					('movl', 'add', 'movl'),
					(u'movl', u'and', u'movl'),
					('movl','imull'),
					(u'movl', u'addl'),
					(u'addl', u'movl'),
					(u'orl', u'movl'),
					(u'movl', u'or', u'neg'),
					(u'movl', u'or', u'movl')
										]:
		return (GadgetType.Calculation, GadgetClass.Basic)

	# mem -> subl -> reg -> addl -> mem
	if pattern in [
		(u'addl', u'subl') ,
		(u'adcl', u'sbbl'),
		(u'movl', u'bswap', u'movl')
							]:
		return (GadgetType.Calculation, GadgetClass.NonBasic)

	# basic adder addl xxx (eax) -> mem
	if pattern in [('addl',), ('subl',)]:
		return (GadgetType.Calculation, GadgetClass.Constant)

		
	
	if pattern in [
		(u'movl', u'add', u'lea', u'cmovz')
							]:
		return (GadgetType.Calculation, GadgetClass.Conditional)		

	##########
	# Setter #
	##########
	
	if pattern in [ ('movl',), # basic setter detect movl xxx (eax) -> mem
					('movb',),
					('movl','mov'), # mov 0x1234 eax -> eax -> movl eax, (ebx) -> mem
					(u'movl', u'xor'),
					(u'movw',),
					(u'andl',),
					(u'orl',),
					(u'movw', u'mov'),
					(u'movb', u'mov', u'mov')
										]:
		return (GadgetType.Setter, GadgetClass.Constant)

	
	return (GadgetType.Unknown, GadgetClass.Unknown)
