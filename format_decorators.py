import re

import sys

# test_t = r''''t
#
# AX=24DD BX=0000 CX=0078 DX=0000 SP=0000 BP=0000 SI=0000 DI=0000
#
# DS=24CD ES=24CD SS=24DD CS=24DF IP=0003 NV UP EI PL NZ NA PO NC
#
# 24DF:0003 8ED8              MOV     DS,AX
#
# '''
test_t = r'''
AX=24DD BX=0000 CX=0078 DX=0000 SP=0000 BP=0000 SI=0000 DI=0000
DS=24CD ES=24CD SS=24DD CS=24DF IP=0003 NV UP EI PL NZ NA PO NC
24DF:0003 8ED8              MOV     DS,AX
'''


test_ts = r'''AX=24DD BX=0000 CX=0078 DX=0000 SP=0000 BP=0000 SI=0000 DI=0000
DS=24DD ES=24CD SS=24DD CS=24DF IP=0005 NV UP EI PL NZ NA PO NC
24DF:0005 B401              MOV     AH,01
AX=01DD BX=0000 CX=0078 DX=0000 SP=0000 BP=0000 SI=0000 DI=0000
DS=24DD ES=24CD SS=24DD CS=24DF IP=0007 NV UP EI PL NZ NA PO NC
24DF:0007 CD21              INT     21
AX=0166 BX=0000 CX=0078 DX=0000 SP=0000 BP=0000 SI=0000 DI=0000
DS=24DD ES=24CD SS=24DD CS=24DF IP=0009 NV UP EI PL NZ NA PO NC
24DF:0009 2C30              SUB     AL,30
'''

class FormatDecorators:
	trace_pat = re.compile(
			r'''.*?  # match unnecessary chars
			(?P<regesters>  # registers
			AX=(?P<AX>\w{4}) \s+
			BX=(?P<BX>\w{4}) \s+
			CX=(?P<CX>\w{4}) \s+
			DX=(?P<DX>\w{4}) \s+
			SP=(?P<SP>\w{4}) \s+
			BP=(?P<BP>\w{4}) \s+
			SI=(?P<SI>\w{4}) \s+
			DI=(?P<DI>\w{4}) \s+
			DS=(?P<DS>\w{4}) \s+
			ES=(?P<ES>\w{4}) \s+
			SS=(?P<SS>\w{4}) \s+
			CS=(?P<CS>\w{4}) \s+
			IP=(?P<IP>\w{4})) \s+
			(?P<flags>\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2}\s\w{2})\s+   #flags
			(?P<address>\w{4}:\w{4}) \s
			(?P<instruct_raw>\w{4}) \s+
			(?P<instruct>\w+\s+[\w,]+)\s*''',
		flags=re.DOTALL|re.VERBOSE)
	@classmethod
	def trace_formatter(cls, method):
		def format_(*args, **kwargs):
			trace_string = method(*args, **kwargs)
			matches = re.finditer(cls.trace_pat, trace_string)
			# if not matches:
			# 	print('error, not matched, trace string:\n', trace_string, file=sys.stderr)
			# 	return None
			return [match.groupdict() for match in matches]
		return format_


if __name__ == '__main__':
	print(re.match(FormatDecorators.trace_pat, test_t).groupdict())
	# for m in re.finditer(FormatDecorators.trace_pat, test_ts):
	# 	print(m.groupdict())
