import getopt, sys, boto3, json
from logging import exception
from operator import ge
import string

from botocore.exceptions import ClientError
from typing import Dict, List

from modules import all_regions, S3, redshift, rds, ecs, eks, cloudFront, dynamoDB

## Global variable
listObj = []

def create_output(output):

	# if path.isfile(filename) is False:
  	# 	raise Exception("File not found")

	with open(output, 'w') as json_file:
		json.dump(listObj, json_file, 
							indent=4,  
							separators=(',',': '))
	print(f'Successfully created results {output} file')

def init(profile:string, region:string, debug:bool):
	
	## ## Global resources
	global_session = boto3.session.Session(profile_name=profile)
	s3_results = S3.read_s3(global_session); listObj.append(s3_results)
	cf_results = cloudFront.read_cloudFront(global_session); listObj.append(cf_results)

	## ## Regional resources
	reg_session = boto3.session.Session(profile_name=profile,region_name=region)

	## Redshift
	redshift_results = {'Redshift':[]}
	if region == "all-regions":
		regions = all_regions.all_regions()
		for reg in regions:
			try:
				session = boto3.session.Session(profile_name=profile,region_name=reg)
				results = redshift.read_redshift(session, reg)
				if results is not None:
					redshift_results["Redshift"].append(results)
				else:
					pass
			except BaseException as be:
				if debug:
					print(be)
				continue
	else:
		try:
			results = redshift.read_redshift(reg_session, region)
			if results is not None:
					redshift_results["Redshift"].append(results)
			else:
				pass
		except BaseException as be:
			if debug:
				print(be)

	listObj.append(redshift_results)

	## RDS
	rds_results = {'RDS':[]}
	if region == "all-regions":
		regions = all_regions.all_regions()
		for reg in regions:
			try:
				session = boto3.session.Session(profile_name=profile,region_name=reg)
				results = rds.read_rds(session, reg)
				if results is not None:
					rds_results["RDS"].append(results).append(results)
				else:
					pass
			except BaseException as be:
				if debug:
					print(be)
	else:
		try:
			results = rds.read_rds(reg_session, region)
			if results is not None:
				rds_results["RDS"].append(results).append(results)
			else:
				pass
		except BaseException as be:
			if debug:
				print(be)

	listObj.append(rds_results)

	## ECS
	ecs_results = {'ECS':[]}
	if region == "all-regions":
		regions = all_regions.all_regions()
		for reg in regions:
			try:
				session = boto3.session.Session(profile_name=profile,region_name=reg)
				results = ecs.read_ecs(session, reg)
				if results is not None:
					ecs_results["ECS"].append(results)
				else:
					pass
			except BaseException as be:
				if debug:
					print(be)
	else:
		try:
			results = ecs.read_ecs(reg_session, region)
			if results is not None:
				ecs_results["ECS"].append(results)
			else:
				pass
		except BaseException as be:
			if debug:
				print(be)

	listObj.append(ecs_results)

	## EKS
	eks_results = {'EKS':[]}
	if region == "all-regions":
		regions = all_regions.all_regions()
		for reg in regions:
			try:
				session = boto3.session.Session(profile_name=profile,region_name=reg)
				results = eks.read_eks(session, reg)
				if results is not None:
					eks_results["EKS"].append(results)
				else:
					pass
			except BaseException as be:
				if debug:
					print(be)
	else:
		try:
			results = eks.read_eks(reg_session, region)
			if results is not None:
				eks_results["EKS"].append(results)
			else:
				pass
		except BaseException as be:
			if debug:
				print(be)
	
	# DynamoDB
	dynamoDB_results = {'DynamoDB':[]}
	if region == "all-regions":
		regions = all_regions.all_regions()
		for reg in regions:
			try:
				session = boto3.session.Session(profile_name=profile,region_name=reg)
				results = dynamoDB.read_dynamodb(session, reg)
				if results is not None:
					dynamoDB_results["DynamoDB"].append(results)
				else:
					pass
			except BaseException as be:
				if debug:
					print(be)
	else:
		try:
			results = dynamoDB.read_dynamodb(reg_session, region)
			if results is not None:
				dynamoDB_results["DynamoDB"].append(results)
			else:
				pass
		except BaseException as be:
			if debug:
				print(be)

	listObj.append(eks_results)

def usage():
	print("usage:")
	print("\tpython3 init.py --profile <profile> --output <output> [options]")
def help():
	print("usage:")
	print("\tpython3 init.py --profile <profile> --output <output> [options]")
	print("\n\t-p, --profile:	AWS profile: ")
	print("\t-o, -output:		output filename")
	print("\nOptions:")
	print("\t-r, --region:	AWS region")
	print("\t-f, --format:	format file for output (JSON, YAML)")
	print("\t-d, --debug:	enable dubug mode")
	exit()

def main():
	# Remove 1st argument from the
	# list of command line arguments
	argumentList = sys.argv[1:]

	# Options
	options = "hp:r:o:f:d"

	# Long options
	long_options = ["help", "profile=","region=", "output=", "format=", "debug"]

	# Main arguments
	profile = None
	region = "all-regions"
	output = None
	format = "JSON"
	debug = False

	try:
		# Parsing argument
		arguments, values = getopt.getopt(argumentList, options, long_options)
		
		# checking each argument
		if arguments:
			for currentArgument, currentValue in arguments:

				if currentArgument in ("-h", "--help"):
					help()
					
				elif currentArgument in ("-p", "--profile"):
					if currentValue:
						profile = currentValue
					else:
						print('Please provide an AWS profile')
						exit()
				
				elif currentArgument in ("-r", "--region"):
					if currentValue:
						region = currentValue
					else:
						region = "all-regions"
					
				elif currentArgument in ("-o", "--output"):
					if currentValue:
						output = str(currentValue)
					else:
						output = "default"
				elif currentValue in ("-d","--debug"):
					debug = True
				else:
					sys.exit('Please provide an AWS profile and an output')
		else:
			usage()
			sys.exit('Please provide an AWS profile and an output')

		if profile and output:
			print(profile)
			print(region)
			print(output)
			print(str(debug))
			init(profile, region, debug)
		else:
			usage()
			sys.exit('Please provide an AWS profile and an output')

	except getopt.error as err:
		# output error, and return with an error code
		print (str(err))
	
	create_output(output)

if __name__ == "__main__":
    main()