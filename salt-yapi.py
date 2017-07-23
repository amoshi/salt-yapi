#!/usr/bin/env python2.7
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import json
from subprocess import Popen, PIPE, STDOUT

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
		
	def do_POST(self):
		content_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(content_length)
		self._set_headers()
		api_json_arr = json.loads(post_data)
		for api_query in api_json_arr:
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
			expr_form = api_query.get("expr_form", "default")
			tgt = api_query["tgt"]
			fun = api_query["fun"]
			username = api_query.get("username", "")
			password = api_query.get("password", "")
			salt_kwarg = api_query.get("kwarg", "")
			if len(api_query["arg"]) > 1:
					saltenv = api_query["arg"][1]
			else:
					saltenv = salt_kwarg.get("saltenv", "base")
					if saltenv == "base":
							saltenv = api_query.get("saltenv", "base")
			salt_arg = api_query["arg"][0]
			client = api_query.get("client", "local")
			eauth = api_query.get("eauth", "")
			pillar = salt_kwarg.get("pillar", "")
			test = salt_kwarg.get("test", False)
			if not test:
					test = api_query.get("test", False)
					
			state_verbose = salt_kwarg.get("state_verbose", False)
			if not state_verbose:
					state_verbose = api_query.get("state_verbose", False)

			timeout = salt_kwarg.get("timeout", 90)
			if timeout == 90:
					timeout = api_query.get("timeout", 90)

			out_format = salt_kwarg.get("out", "json")
			if out_format == "json":
					out_format = api_query.get("out_format", "json")

			batch_size = salt_kwarg.get("batch-size", 0)
			if batch_size == 0:
					batch_size = api_query.get("batch-size", "")

			if batch_size == "":
					batch_size_ins = ""
			else:
					batch_size_ins = " --batch-size " + str(batch_size) + " "

			if expr_form == "default":
					expr_form_cli = ""
			else:
					expr_form_cli = "--" + expr_form

			call_cli_cmd = "salt --state_verbose=" + str(state_verbose) + batch_size_ins + " -t " + str(timeout) + " --out=" + out_format + " " + expr_form_cli + " " + tgt + " " + fun + " " + salt_arg + " saltenv="  + saltenv +  " pillar='" + json.dumps(pillar) + "' test=" + str(test)

			salt_call = Popen(call_cli_cmd, shell=True, stdin=PIPE, stdout=PIPE,
			stderr=STDOUT, close_fds=True)
			#self.wfile.write(call_cli_cmd)
			self.wfile.write(salt_call.stdout.read())
				
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
