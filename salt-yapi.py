#!/usr/bin/env python2.7
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import json
from collections import defaultdict
from subprocess import Popen, PIPE, STDOUT
from pam import authenticate
#from notifications import send_notification

allowed_fun = ["state.sls", "state.highstate", "cmd.run", "pillar.get", "grains.get", "grains.item", "grains.setval", "grains.setvals", "service.restart", "service.status", "test.ping", "pkg.install"]

class S(BaseHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		self.send_header("Content-type", "application/json")
		self.end_headers()

	def do_GET(self):
		self.send_response(403)
		self.end_headers()
		self.wfile.write("Method GET not allowed\n")

	def do_HEAD(self):
		self.send_response(403)
		self.end_headers()

	def changesonlyout(self, salt_out):
		rsr={}
		rsr['return']=[]
		print(salt_out)
		for return_ in salt_out['return']:
			res = defaultdict(dict)
			for r  in return_:
				for k, v in return_[r].items():
					if type(v) is not int:
						if v['changes']:
							res[r][k] = v
			rsr['return'].append(res)
		return(rsr)
	def user_validate(self, username, password):
		return authenticate(username, password)

	def do_POST(self):
		content_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(content_length)
		self._set_headers()

		rsend = {}
		rsend["return"] = []
		api_json_arr = json.loads(post_data)
		fd = open("/var/log/salt-yapi.log", "a")
		fd.write("\n-----\n")
		for api_query in api_json_arr:
			fd.write(json.dumps(api_json_arr))
			call_cli_cmd = []
			call_cli_cmd.append("salt")

			if api_query["tgt"] is None:
				self.wfile.write('{"type":"error","class":"not defined","variable":"tgt","msg":"tgt is not defined"}\n')
				return
			if api_query["fun"] is None:
				self.wfile.write('{"type":"error","class":"not defined","variable":"fun","msg":"fun is not defined"}\n')
				return
			if api_query["eauth"] is None:
				self.wfile.write('{"type":"error","class":"not defined","variable":"eauth","msg":"eauth is not defined"}\n')
				return
			if api_query["username"] is None:
				self.wfile.write('{"type":"error","class":"not defined","variable":"username","msg":"username is not defined"}\n')
				return
			if api_query["password"] is None:
				self.wfile.write('{"type":"error","class":"not defined","variable":"password","msg":"password is not defined"}\n')
				return

			salt_args = api_query.get("arg", "")
			username = api_query.get("username", "")
			password = api_query.get("password", "")
			salt_kwarg = api_query.get("kwarg", {})
			if self.user_validate(username, password) == False:
				self.wfile.write('{"type":"error","class":"login","variable":"user","msg":"failed login"}\n')
				return

			state_verbose = salt_kwarg.get("state_verbose", False)
			if not state_verbose:
				state_verbose = api_query.get("state_verbose", False)
			call_cli_cmd.append("--state_verbose={state_verbose}".format(state_verbose=state_verbose))

			timeout = salt_kwarg.get("timeout", 90)
			if timeout == 90:
				timeout = api_query.get("timeout", 90)
			call_cli_cmd.append("-t {timeout}".format(timeout=timeout))

			out_format = salt_kwarg.get("out", "json")
			if out_format == "json":
				out_format = api_query.get("out_format", "json")
			call_cli_cmd.append("--out={out_format}".format(out_format=out_format))
			if out_format == "json":
				call_cli_cmd.append("-s")

			if ('batch_size' in salt_kwarg.keys() or 'batch_size' in api_query.keys()):
				bsname = 'batch_size'
			else:
				bsname = 'batch-size'
			batch_size = salt_kwarg.get(bsname, None)
			if batch_size is None:
				batch_size = api_query.get(bsname, None)
			if batch_size is not None:
				call_cli_cmd.append("--batch-size={batch_size}".format(batch_size=batch_size))

			if ('batch_wait' in salt_kwarg.keys() or 'batch_wait' in api_query.keys()):
				bwname = 'batch_wait'
			else:
				bwname = 'batch-wait'
			batch_wait = salt_kwarg.get(bwname, None)
			if batch_wait is None:
				batch_wait = api_query.get(bwname, None)
			if batch_wait is not None:
				call_cli_cmd.append("--batch-wait={batch_wait}".format(batch_wait=batch_wait))

			expr_form = api_query.get("expr_form", None)
			if expr_form is not None:
				call_cli_cmd.append("--{expr_form}".format(expr_form=expr_form))

			tgt = api_query["tgt"]
			call_cli_cmd.append("'{tgt}'".format(tgt=tgt))

			fun = api_query["fun"]
			if fun in allowed_fun:
				call_cli_cmd.append(fun)
			else:
				self.wfile.write('{"type":"error","class":"not allowed","variable":"fun","msg":"fun ' + fun + ' is not allowed"}\n')
				return

			if len(api_query.get("arg","")) != 0:
				salt_arg = api_query["arg"][0]
				call_cli_cmd.append(salt_arg)

			if len(api_query.get("arg","")) > 1:
				if ( fun.startswith("grains") ):
					var2 = api_query["arg"][1]
					call_cli_cmd.append("{var2}".format(var2=var2))
				else:
					saltenv = api_query["arg"][1]
					call_cli_cmd.append("saltenv={saltenv}".format(saltenv=saltenv))
			else:
				saltenv = salt_kwarg.get("saltenv", None)
				if saltenv is None:
					saltenv = api_query.get("saltenv", None)
				if saltenv is not None:
					call_cli_cmd.append("saltenv={saltenv}".format(saltenv=saltenv))

			test = salt_kwarg.get("test", None)
			if test is None:
				test = api_query.get("test", False)
			if test:
				call_cli_cmd.append("test=True")
				
			client = api_query.get("client", "local")
			eauth = api_query.get("eauth", "")
			pillar = salt_kwarg.get("pillar", None)
			if pillar is not None:
				call_cli_cmd.append("pillar='{pillar}'".format(pillar=json.dumps(pillar)))
					
			fd.write("\n++++\n")
			call_cli_str = " ".join(call_cli_cmd)
			fd.write("[" + tgt + "] " + call_cli_str)
			#send_notification(api_json_arr, call_cli_str, " ")
			print call_cli_str
			salt_call = Popen(call_cli_str, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
			salt_output = salt_call.stdout.read()
			fd.write("\n++++\n")
			fd.write(salt_output)


			rsend["return"].append(json.loads(salt_output.strip()))

		fd.write("\n++++\n")
		fd.write("[" + tgt + "] " + json.dumps(rsend))
		fd.write("\n-----\n")
		#send_notification(api_json_arr, call_cli_str, " ")
		fd.close()
		if ( fun == "test.ping" ):
			self.wfile.write(json.dumps(rsend))
		elif (fun == "grains.setvals"):
			self.wfile.write(json.dumps(rsend))
		elif (fun == "grains.setval"):
			self.wfile.write(json.dumps(rsend))
		else:
			self.wfile.write(json.dumps(self.changesonlyout(rsend)))
				
def run(server_class=HTTPServer, handler_class=S, port=8082):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	print 'Starting httpd...'
	httpd.serve_forever()

if __name__ == "__main__":
	from sys import argv

	if len(argv) == 2:
		run(port=int(argv[1]))
	else:
		run()

