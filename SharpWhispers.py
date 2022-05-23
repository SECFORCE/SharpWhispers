#!/usr/bin/python3

import argparse
import json
import os
import random
import struct

class SysWhispers(object):

	def merge_dict(self, dic1, dic2):
		# https://stackoverflow.com/questions/38987/how-do-i-merge-two-dictionaries-in-a-single-expression-take-union-of-dictionari
		return { **dic1, **dic2}

	def merge_list(self, l1, l2):
		return l1 + l2


	def __init__(self):
		self.seed = random.randint(2 ** 28, 2 ** 32 - 1)
		
		# Native Types
		typedefs_native_dinvoke: list = json.load(open('./data/json/typedefs_native-DInvoke.json'))
		typedefs_native_additional: list = json.load(open('./data/json/typedefs_native-Additional.json'))

		# Load All Natives
		self.typedefs_native: list = self.merge_list(typedefs_native_dinvoke, typedefs_native_additional)
		# DInvoke Win32 and WinNT types		
		self.typedefs_kernel32: list = json.load(open('./data/json/typedefs_kernel32.json'))
		self.typedefs_winnt: list = json.load(open('./data/json/typedefs_winnt.json'))


		prototypes_dinvoke: dict = json.load(open('./data/json/Delegates-DInvoke.json'))
		prototypes_additional: dict = json.load(open('./data/json/Delegates-Additional.json'))
		
		# Delegates
		self.prototypes: dict = self.merge_dict(prototypes_dinvoke,prototypes_additional)


		function_wrappers_dinvoke: dict = json.load(open('./data/json/function_wrappers-DInvoke.json'))
		function_wrappers_additional: dict = json.load(open('./data/json/function_wrappers-Additional.json'))

		# Function prototypes
		self.function_wrappers: dict = self.merge_dict(function_wrappers_dinvoke,function_wrappers_additional)



		# Constants
		self.NATIVE = "Data.Native"
		self.KERNEL32 = "Data.Win32.Kernel32"
		self.WINNT = "Data.Win32.WinNT"

	def generate(self, function_names: list = (), basename: str = 'SharpWhispers'):
		if not function_names:
			function_names = list(self.prototypes.keys())
		elif any([f not in self.prototypes.keys() for f in function_names]):
			raise ValueError('Prototypes are not available for one or more of the requested functions.')


		outdir = "out/"

		basename_sharpasm = outdir + "sharpASM"

		basename_sharpwhispers = outdir + basename
		basename_PEB = outdir + "PEB"

		basename_syscalls = outdir + basename + "-syscalls"
		basename_typedefs_native = outdir + basename + "-types-native"
		basename_typedefs_win32 = outdir + basename + "-types-win32"
		basename_delegates = outdir + basename + "-Delegates"
		basename_typedefs_pe = outdir + basename + "-types-PE"



		# Write PEB.cs file
		# This file contains functions to retrieve PEB using SharpASM
		with open('./data/templates/PEB.cs', 'rb') as base_source:
			with open(f'{basename_PEB}.cs', 'wb') as output_source:
				base_source_contents = base_source.read().decode()
				#base_source_contents = base_source_contents.replace('TODO', os.path.basename(basename_dinvoke))
				output_source.write(base_source_contents.encode())

		# Write SharpASM.cs file
		# This file contains the code to call ASM code
		with open('./data/templates/SharpASM.cs', 'rb') as base_source:
			with open(f'{basename_sharpasm}.cs', 'wb') as output_source:
				base_source_contents = base_source.read().decode()
				#base_source_contents = base_source_contents.replace('SharpASM', os.path.basename(basename_sharpasm))
				output_source.write(base_source_contents.encode())

		# Write SharpWhispers.cs file
		# This file contains the code to solve the system call numbers
		with open('./data/templates/SharpWhispers.cs', 'rb') as base_source:
			with open(f'{basename_sharpwhispers}.cs', 'wb') as output_source:
				base_source_contents = base_source.read().decode()
				base_source_contents = base_source_contents.replace('<SEED_VALUE>', f'"{self.seed:08X}"', 1)
				base_source_contents = base_source_contents.replace('SharpWhispers', os.path.basename(basename_sharpwhispers))
				output_source.write(base_source_contents.encode())


		# Write Delegates
		# This file contains the Delegates of the included system calls
		with open('./data/templates/Delegates.cs', 'rb') as base_source:
			with open(f'{basename_delegates}.cs', 'wb') as output_source:
				base_source_contents = base_source.read().decode()
				
				delegates = ""
				for function_name in function_names:
					delegates += self._get_function_prototype(function_name) + '\n\n'

				base_source_contents = base_source_contents.replace('<DELEGATES>', delegates, 1)


				output_source.write(base_source_contents.encode())


		# Write Syscalls.cs file
		# This file contains the code to execute the system calls
		with open('./data/templates/Syscalls.cs', 'rb') as base_source:
			with open(f'{basename_syscalls}.cs', 'wb') as output_source:
				base_source_contents = base_source.read().decode()
				base_source_contents = base_source_contents.replace('SharpWhispers', os.path.basename(basename_sharpwhispers))
				

				# Write Function Wrappers
				function_wrappers = self._get_function_wrapper(function_names)
				base_source_contents = base_source_contents.replace('<FUNCTION_HELPERS>', function_wrappers, 1)
					

				# Write file
				output_source.write(base_source_contents.encode())

		# Write typedefs


		# Native
		print("[i] Writing "+ self.NATIVE +" typedefs...")

		with open("./data/templates/TypedefsNative.cs", 'rb') as base_source:
			with open(f'{basename_typedefs_native}.cs','wb') as output_source:
				base_source_contents = base_source.read().decode()

				# Return type NTSTATUS is already in the template because we always need it
							
				# Write typedefs
				typedefs = ""
				for typedef in self._get_typedefs(function_names, self.NATIVE):
					typedefs += typedef + '\n\n'

				base_source_contents = base_source_contents.replace('<TYPEDEFS>', typedefs, 1)
				# Write file
				output_source.write(base_source_contents.encode())


		# Win32
		print("[i] Writing Win32 typedefs...")

		with open("./data/templates/TypedefsWin32.cs", 'rb') as base_source:
			with open(f'{basename_typedefs_win32}.cs','wb') as output_source:
				base_source_contents = base_source.read().decode()
				
				# Write typedefs Kernel32
				print("\t[>] Writing "+ self.KERNEL32 +" typedefs...")

				typedefs = ""
				for typedef in self._get_typedefs(function_names, self.KERNEL32):
					typedefs += typedef + '\n\n'

				base_source_contents = base_source_contents.replace('<TYPEDEFS_KERNEL32>', typedefs, 1)
				

				# Write typedefs WinNT
				print("\t[>] Writing "+ self.WINNT +" typedefs...")

				typedefs = ""
				for typedef in self._get_typedefs(function_names, self.WINNT):
					typedefs += typedef + '\n\n'

				base_source_contents = base_source_contents.replace('<TYPEDEFS_WINNT>', typedefs, 1)


				# Write file
				output_source.write(base_source_contents.encode())


		# PE
		# Write TypedefsPE.cs file
		# This file contains PE Definitions needed by SharpWhispers.cs file
		# We always need it
		with open('./data/templates/TypedefsPE.cs', 'rb') as base_source:
			with open(f'{basename_typedefs_pe}.cs', 'wb') as output_source:
				base_source_contents = base_source.read().decode()
				#base_source_contents = base_source_contents.replace('TODO', os.path.basename(basename_typedefs_pe))
				output_source.write(base_source_contents.encode())



		print('Complete! Files written to:')
		print(f'\t{basename_sharpwhispers}.cs')
		print(f'\t{basename_sharpasm}.cs')
		print(f'\t{basename_PEB}.cs')
		print(f'\t{basename_syscalls}.cs')
		print(f'\t{basename_typedefs_win32}.cs')
		print(f'\t{basename_typedefs_native}.cs')
		print(f'\t{basename_delegates}.cs')
		print(f'\t{basename_typedefs_pe}.cs')


	def _get_function_wrapper(self, function_names: list) -> str:
		function_wrappers = ""

		for f in function_names:
			zw_fucntion = f.replace("Nt","Zw")
			orig_fcall = "DynamicSysInvoke.DynamicSyscallInvoke(\"" + f
			new_fcall = "DynamicSysInvoke.DynamicSyscallInvoke(\"" + self._get_function_hash(zw_fucntion)

			wrapper = self.function_wrappers[f]
			wrapper = wrapper.replace(orig_fcall,new_fcall)
			
			function_wrappers += wrapper
			function_wrappers += "\n"
		return function_wrappers

	def _get_typedefs(self, function_names: list, TYPEDEF_CLASS: str) -> list:
		
		if(TYPEDEF_CLASS == self.NATIVE):
			typedefs_file = self.typedefs_native

			# Include the typedefs needed by the boilerplate code (e.g. SharpWhispers.cs , SharpWhispers-syscalls.cs)
			# PROCESS_BASIC_INFORMATION is needed by SharpWhiseprs-syscalls.cs
			# LIST_ENTRY is needed by SharpWhispers.cs
			# PE class (in SharpWhispers-types-PE.cs) is always needed by SharpWhispers.cs
			# PE class needs the following data types
			# - LIST_ENTRY
			# - UNICODE_STRING
			mandatory_types = ["PROCESS_BASIC_INFORMATION", "LIST_ENTRY", "UNICODE_STRING", "NTSTATUS"]

		if(TYPEDEF_CLASS == self.KERNEL32):
			typedefs_file = self.typedefs_kernel32
			mandatory_types = []
		
		if(TYPEDEF_CLASS == self.WINNT):
			typedefs_file = self.typedefs_winnt
			mandatory_types = []


		def _names_to_ids(names: list) -> list:
			return [next(i for i, t in enumerate(typedefs_file) if n in t['identifier']) for n in names]

		# Determine typedefs to use.
		used_typedefs = mandatory_types
		for function_name in function_names:
			print("\t\tFunction: ", function_name)

			for param in self.prototypes[function_name]['params']:
				# strip NAMESPACE.CLASS.	
				delimiter = TYPEDEF_CLASS + "."
				param_type = param['type'].split(delimiter)
				
				if(len(param_type) == 2):
					# The parameter is in the class we are looking for
					param_type = param_type[1]
				else:
					# The parameter is *not* in the class we we are looking for, we just leave it as is
					param_type = param_type[0]

				if list(filter(lambda t: param_type in t['identifier'], typedefs_file)):
					print("\t\tType to add: ", param_type)			
					if param_type not in used_typedefs:
						used_typedefs.append(param_type)

		# Resolve typedef dependencies.
		i = 0
		typedef_layers = {i: _names_to_ids(used_typedefs)}
		while True:
			# Identify dependencies of current layer.
			more_dependencies = []
			for typedef_id in typedef_layers[i]:
				more_dependencies += typedefs_file[typedef_id]['dependencies']
			more_dependencies = list(set(more_dependencies))  # Remove duplicates.


			if more_dependencies:
				# Create new layer.
				i += 1
				typedef_layers[i] = _names_to_ids(more_dependencies)
			else:
				# Remove duplicates between layers.
				for k in range(len(typedef_layers) - 1):
					typedef_layers[k] = set(typedef_layers[k]) - set(typedef_layers[k + 1])
				break

		# Get code for each typedef.
		typedef_code = []
		for i in range(max(typedef_layers.keys()), -1, -1):
			for j in typedef_layers[i]:
				print("\tAdding " + typedefs_file[j]['identifier'] + " to the source")
				typedef_code.append(typedefs_file[j]['definition'])

		return typedef_code





	# Get Delegates
	def _get_function_prototype(self, function_name: str) -> str:
		# Check if given function is in syscall map.
		if function_name not in self.prototypes:
			raise ValueError('Invalid function name provided.')

		num_params = len(self.prototypes[function_name]['params'])
		return_type = self.prototypes[function_name]['type']
		signature = '[UnmanagedFunctionPointer(CallingConvention.StdCall)]\n'
		signature += f'public delegate {return_type} {function_name}('
		if num_params:
			for i in range(num_params):
				param = self.prototypes[function_name]['params'][i]
				signature += '\n\t'
				signature += 'in ' if param['in'] else ''
				signature += 'out ' if param['out'] else ''
				signature += 'ref ' if param['ref'] else ''
				signature += f'{param["type"]} {param["name"]}'
				#signature += ' OPTIONAL' if param['optional'] else ''
				signature += ',' if i < num_params - 1 else ');'
		else:
			signature += ');'

		return signature

	def _get_function_hash(self, function_name):
		# https://gist.github.com/jasny/2200f68f8109b22e61863466374a5c1d
		import hashlib
		import hmac
		import base64

		#key = str(self.seed)

		key = f'{self.seed:08X}'

		message = bytes(function_name, 'utf-8')
		secret = bytes(key, 'utf-8')

		hash = hmac.new(secret, message, hashlib.md5)

		# to lowercase hexits
		hash.hexdigest()

		digest = hash.digest()

		str_digest = digest.hex().upper()
		return str_digest









if __name__ == '__main__':
	banner = '''
   ______               _      ____   _                    
  / __/ /  ___ ________| | /| / / /  (_)__ ___  ___ _______
 _\ \/ _ \/ _ `/ __/ _ \ |/ |/ / _ \/ (_-</ _ \/ -_) __(_-<
/___/_//_/\_,_/_/ / .__/__/|__/_//_/_/___/ .__/\__/_/ /___/
                 /_/                    /_/                

@d_glenx
@SECFORCE_LTD

=============================================================

'''


	print(banner)

	parser = argparse.ArgumentParser()
	parser.add_argument('-p', '--preset', help='Preset ("all", "common", "dinvoke")', required=False)
	parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
	parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', required=True)
	parser.set_defaults(feature=False)
	args = parser.parse_args()

	
	sw = SysWhispers()

	if args.preset == 'all':
		print('All functions selected.\n')
		sw.generate(basename=args.out_file)

	elif args.preset == 'common':
		print('Common functions selected.\n')
		sw.generate(
			['NtCreateProcess',
			 'NtCreateThreadEx',
			 'NtOpenProcess',
			 'NtOpenProcessToken',
			 'NtTestAlert',
			 'NtOpenThread',
			 'NtSuspendProcess',
			 'NtSuspendThread',
			 'NtResumeProcess',
			 'NtResumeThread',
			 'NtGetContextThread',
			 'NtSetContextThread',
			 'NtClose',
			 'NtReadVirtualMemory',
			 'NtWriteVirtualMemory',
			 'NtAllocateVirtualMemory',
			 'NtProtectVirtualMemory',
			 'NtFreeVirtualMemory',
			 'NtQuerySystemInformation',
			 'NtQueryDirectoryFile',
			 'NtQueryInformationFile',
			 'NtQueryInformationProcess',
			 'NtQueryInformationThread',
			 'NtCreateSection',
			 'NtOpenSection',
			 'NtMapViewOfSection',
			 'NtUnmapViewOfSection',
			 'NtAdjustPrivilegesToken',
			 'NtDeviceIoControlFile',
			 'NtQueueApcThread',
			 'NtWaitForMultipleObjects'],
			basename=args.out_file)

	elif args.preset == 'dinvoke':
		print('Common functions selected.\n')
		sw.generate(
			['NtCreateThreadEx',
			'NtCreateSection',
			'NtUnmapViewOfSection',
			'NtMapViewOfSection',
			'NtQueryInformationProcess',
			'NtAllocateVirtualMemory',
			'NtFreeVirtualMemory',
			'NtProtectVirtualMemory',
			'NtWriteVirtualMemory',
			'NtOpenFile',
			'NtReadVirtualMemory',
			'NtQueryVirtualMemory',
			'NtOpenProcess'],
			basename=args.out_file)

	elif args.preset:
		print('ERROR: Invalid preset provided. Must be "all", "common" or "dinvoke".')

	elif not args.functions:
		print('ERROR:   --preset XOR --functions switch must be specified.\n')
		print('EXAMPLE: ./syswhispers.py --preset common --out-file syscalls_common')
		print('EXAMPLE: ./syswhispers.py --functions NtTestAlert,NtGetCurrentProcessorNumber --out-file syscalls_test')

	else:
		functions = args.functions.split(',') if args.functions else []
		sw.generate(functions, basename=args.out_file)
