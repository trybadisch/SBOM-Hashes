import json
import requests
import sys

import xml.etree.ElementTree as ET

if len(sys.argv) != 4:
    print('[!] Usage: ./'+sys.argv[0]+' SBOM.json output.json error_log.txt')
    sys.exit()

filename 	= sys.argv[1]
output 		= sys.argv[2]
error_log  	= sys.argv[3]
log = ""

with open(filename, 'r') as f:
	sbom = json.load(f)

for idx, component in enumerate(sbom["components"]):
	ref = component["bom-ref"].split(':')[1]
	manager = ref.split('/')[0]
	name = component["name"]
	version = component["version"]

	try: 
		if manager == "npm":

			dict_fix = { "jqueryui":"jquery-ui",
				"modernizr":"npm-modernizr"}  # update package name fix

			for key in dict_fix:
				if key in name:
					name = name.replace(key, dict_fix[key])

			url = "https://registry.npmjs.org/"  # https://registry.npmjs.org/$package .versions[$version].dist.integrity
			res = json.loads(requests.get(url+name).text)
			checksum = res['versions'][version]["dist"]["integrity"]
			component["hashes"].append({"alg":checksum.split('-')[0], "content":checksum.split('-')[1]})

		if manager == "nuget":
			
			url = "https://www.nuget.org/api/v2/Packages"  # https://www.nuget.org/api/v2/Packages(Id='[$package]',Version='[$version]')
			res = requests.get(url+"(Id='"+name+"',Version='"+version+"')")
			tree = ET.ElementTree(ET.fromstring(res.text))
			root = tree.getroot()
			for property in root.iter('{http://schemas.microsoft.com/ado/2007/08/dataservices/metadata}properties'):
				checksum = property.find('{http://schemas.microsoft.com/ado/2007/08/dataservices}PackageHash').text
				algo = property.find('{http://schemas.microsoft.com/ado/2007/08/dataservices}PackageHashAlgorithm').text

			component["hashes"].append({"alg":algo, "content":checksum})

		if manager == "maven":
			
			name, artifact = name.split(':')
			name = name.replace(':','/').replace('.','/')+'/'+artifact		

			url = "https://repo1.maven.org/maven2/"  # https://repo1.maven.org/maven2/$group/$artifact/$version/

			res = requests.get(url+name+'/'+version+'/'+artifact+'-'+version+'.jar.sha1')
			checksum = (res.text.split(' ')[0].strip())
			algo = "SHA1"

			if res.status_code == 200:
				component["hashes"].append({"alg":algo, "content":checksum.strip()})

			else:
				error = '[!] ' + ref + " not found: " + url+name+'/'+version+'/'+artifact+'-'+version+'.jar.sha1'
				print(error)
				log += error+'\n'

		if manager == "python":

			url = "https://pypi.org/pypi/"  # https://pypi.org/pypi/$package/$version/json
			res = json.loads(requests.get(url+name+'/'+version+'/json').text)
			algo = "SHA256"

			for url in res["urls"]:
				checksum = (url["digests"]["sha256"])
				component["hashes"].append({"alg":algo, "content":checksum})

		# CPP packages dependant on arch > write to error log
		if manager == "cpp":

			error = "[!] CPP package detected, add manually: " + ref
			print(error)
			log += error+'\n'

	except Exception as e:
		error = '[!] ' + type(e).__name__ +' '+ str(e) + " = " + ref
		print(error)
		log += error+'\n'

with open(output, 'w') as f:
	json.dump(sbom, f)

with open(error_log, 'w') as f:
	f.write(log)