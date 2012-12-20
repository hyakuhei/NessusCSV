import csv
import sys,os,socket

class importer:
	def __init__(self):
		self.ip2host = {}
		if hasattr(socket, 'setdefaulttimeout'):
			socket.setdefaulttimeout(2)

		self.fuzzyCache = []


	def readin(self,filepath):
		r = csv.DictReader(open(filepath),delimiter=',',quotechar='"')
		ret = []

		for row in r:
			ret.append(row)

		return ret

	def sortBy(self,data,key_):
		return data.sort(key=itemgetter(key_))

	"""
	Operates on a list of dictionaries
	"""
	def pruneBy(self,data,key,value):
		for d in data:
			if d[key] == value:
				data.remove(d)

	"""
	Operates on a list of dictionaries
	"""
	def pruneByCopy(self,data,key,value):
		newData = []
		for d in data:
			if d[key] != value:
				newData.append(d)

		return newData
		
	def filterBy(self,data,key,value):
		newlist = filter(lambda x: x[key] == value,data)
		return newlist	

	def uniqueValues(self,data,key):
		values = []
		for d in data:
			if d[key] not in values:
				values.append(d[key])
		return values

	def dictionaryGroup(self,data_,key):
		idents = {}

		for d in data_:
			idents.setdefault(d[key],[]).append(d)

		return idents

	def readinMultiple(self,pathlist):
		ret = []
		for filepath in pathlist:
			ret.extend(self.readin(filepath))

		return ret

	def fuzzyGroup(self,domain):
		groups = {
			'Swift':["store","storage","swift","sw.","sw-",'proxy','object'],
			'Glance':['gl.','gl-','glance'],
			'Bock':['bock','bk.','bk-'],
			'Control Services':["cs.","cs-","control","controlservices"],
			'Devex':["console","devex","manage","github","git.hpcloud",'dx-','market','sendgrid'],
			'Networking':['.net.'],
			'RnD':[".rndc.",".rnda.",".rndb."],
			'Chef':['chef-','chef.'],
			'Nova':["compute","nv-","nv.","nova"],
			'LoadTest':['loadtest'],
			'Operations':['ops-','.ops.','ops.','dhcp','syslog','proxy','mirror','holly'],
			'Metering':['meter','mb-'],
			'API':['api-','apigateway'],
			'NoC':['noc']
		}
		
		dom = domain.lower()

		"""
		for group in groups.keys():
			for value in groups[group]:
				if value in dom:#
					if value == 'proxy':
						print dom
					return group

		#Alternative Function, that checks we're not double-matching groups, useful for debugging the group-dictionary
		"""
		for group in groups.keys():
			matches = []
			for value in groups[group]:
				if value in dom:
					if group not in matches:
						matches.append(group)

			if len(matches) > 1:
				print "%s matches %s" % (domain, ", ".join(matches))
				return 'MultiMatch'
			elif len(matches) == 1:
				return matches[0]

		#This stops us spamming the output
		if domain not in self.fuzzyCache:
			print 'Could not find fuzzy match for %s' % domain
			self.fuzzyCache.append(domain)

		return 'Unknown'

	def mixinDomain(self,data):
		domain = ""
		for d in data:
			if d['Host'] not in self.ip2host:
				try:
					domain = socket.gethostbyaddr(d['Host'])[0]
				except:
					domain = 'Unknown'
					self.ip2host[d['Host']] = 'Unknown'
			else:
				domain = self.ip2host[d['Host']]
			
			d['Domain'] = domain
			if domain != 'Unknown':
				d['Group'] = self.fuzzyGroup(domain)
			else:
				d['Group'] = 'Unknown'

	class Metrics:
		def __init__(self,funcs):
			self.funcs = funcs

		def metrics(self,data):
			hostg = funcs.dictionaryGroup(data,'Host')
			self.num_hosts = len(hostg)

if __name__ == '__main__':
	i = importer()

	fileList = []
	target = sys.argv[1]
	try:

		fp = open(target,'rb')
		close(fp)
		fileList.append(target)
	except:
		print 'Couldnt open %s as file' % target
		dirList = os.listdir(target)
		for f in dirList:
			if f[-4:] == '.csv':
				fileList.append(target+"/"+f)

#	raise Exception("BREAK BREAK BREAK")

	print '...Reading'
	data = i.readinMultiple(fileList)

	#We need to clear out all the None risk / for info results.
	print '...Pruning out 0-risk issues'
	data = i.pruneByCopy(data,'Risk','None')

	print '...Pruning "Unsupported Unix Operating System" messages'
	data = i.pruneByCopy(data,'Name','Unsupported Unix Operating System')

	print '...Mixing in Domains'
	i.mixinDomain(data)
	
	print '...Sorting by Host'
	hostg = i.dictionaryGroup(data,'Host')
	
	detected = len(data)
	
	criticals = i.filterBy(data,'Risk','Critical')
	criticalg = i.dictionaryGroup(criticals,'Plugin ID')
	hostCriticalg = i.dictionaryGroup(criticals,'Host')

	hostg = i.dictionaryGroup(data,'Host')
	vulng = None
	vulns = None

	print "---Host Summary---"
	print "%i hosts detected" % detected
	print "%i hosts reachable" % len(hostg)
	print "%i hosts have critical vulns" % len(hostCriticalg)

	print "---Critical Vulnerability Overview---"
	vulns = i.filterBy(data,'Risk','Critical')
	vulng = i.dictionaryGroup(vulns,'Plugin ID')

	print "%i individual software packages with %s vulnerabilities" % (len(vulng),'Critical')
	for pid in vulng.keys():
		location = None
		if vulng[pid][0]['Port'] == '0':
			location = 'Local'
		else:
			location = 'Remote'
		hosts_with_vuln = i.dictionaryGroup(vulng[pid],'Host')
		print "Hosts: %i, Type: %s, Desc: %s" % (len(hosts_with_vuln),location,vulng[pid][0]['Name'])

	#TODO try replacing 'data' with 'criticals'
	print "---Team Summary---"
	groupg = i.dictionaryGroup(criticals,'Group')
	print 'Identified %i groups' % len(groupg)

	for group in groupg.keys():
		subhostgroupg = i.dictionaryGroup(groupg[group],'Host')
		print "###%s" % group
		print "###%i hosts have vulnerabilities" % len(subhostgroupg)
		# Print Unknown
		#if 'Unknown' in group:
		#	for sub in subhostgroupg.keys():
		#		print sub
		groupvulng = i.dictionaryGroup(groupg[group], 'Plugin ID')
		for pid in groupvulng.keys():
			affectedHostsInGroup = i.dictionaryGroup(groupvulng[pid],'Host')
			print "%s : %i" % (groupvulng[pid][0]['Name'],len(affectedHostsInGroup))







