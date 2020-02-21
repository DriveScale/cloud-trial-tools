#!/usr/bin/env python3

# Copyright 2019 DriveScale Inc.

"""aws_poc.py -- manage DriveScale demo domains from published AMIs"""

import argparse
from collections import defaultdict, namedtuple
import inspect
import ipaddress
import json
import os
from os.path import expanduser
import re
import sys
from urllib.request import urlopen

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    if __name__ == '__main__':
        print('Cannot import required library boto3')
        print()
        print('boto3 may be available with one of the following depending')
        print('on your platform:')
        print('    apt-get install python3-boto3')
        print('    yum install python3-boto3')
        print('    pip install boto3')
        sys.exit(1)
    raise

try:
    from yaml import dump as yaml_dump
except ImportError:
    yaml_dump = None

try:
    from packaging.version import parse as packaging_version_parse
except ImportError:
    packaging_version_parse = None


# DriveScale account that publishes POC images.
DRIVESCALE_IMAGES_ACCOUNT = '177855195942'

# Created instances are given these tags.  The first identifies the domain
# (management domain) and the second identifies the function of the instance.
DOMAIN_TAG = 'drivescale:domain'
ROLE_TAG = 'drivescale:role'

# Used for resources that are not set up atomically (security groups).
INITIALIZED_TAG = 'drivescale:initialized'

# This is used on volumes, which do not have a durable association with a VPC,
# to keep track of which domain they go with.
VOLUME_VPC_TAG = 'drivescale:domain-vpc-id'

# For resources that don't have a name, the AWS console displays or edits this
# tag as the name.
NAME_TAG = 'Name'

# If this key pair exists, it is used for access to new instances if no key
# pair is specified.
DEFAULT_KEY_PAIR = 'drivescale-default'


# These strings appear in the name of published images, and are used in
# association with the ROLE_TAG to identify the function of an instance.  In
# particular the management server is tagged with COMPOSER_ROLE, which is how
# we identify it so that servers and adapters can be configured with its IP
# address.
COMPOSER_ROLE = 'composer'   # Provides managment service.
ADAPTER_ROLE = 'adapter'     # Makes storage available on network.
SERVER_ROLE = 'server'       # Application servers consume storage.
ALL_ROLES = (COMPOSER_ROLE, ADAPTER_ROLE, SERVER_ROLE)


# Only currently supported region (AMIs are only published here.)
REGION = 'us-east-2'


# Filter accepting all instance states except terminated.
INSTANCE_NOT_TERMINATED_FILTER = {
    'Name': 'instance-state-name',
    'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']
}

DUPLICATE_PERMISSION_ERROR = 'InvalidPermission.Duplicate'
DUPLICATE_KEY_PAIR_ERROR = 'InvalidKeyPair.Duplicate'
KEY_PAIR_NOT_FOUND_ERROR = 'InvalidKeyPair.NotFound'


# These user-data segments use and enable our cloud-init module.

def cloud_config(x):
    if yaml_dump:
        return '#cloud-config\n' + yaml_dump(x, default_flow_style=False)
    else:
        return '#cloud-config\n' + json.dumps(x)


def dms_user_data():
    """cloud-config user-data segment for DMS

    Configures the instance to generate required keys and configure itself as
    the single zookeeper instance.  These behaviors are only appropriate for a
    singleton, non-HA configuration."""
    return cloud_config({
        'drivescale': {
            'make_dms_secrets': True,
            'zk_server_self': True,
        }
    })


def client_user_data(dms_ip):
    """cloud-config user-data segment for server or adapter

    Configures the instance with the (private) IP of the given composer
    instance as the ZooKeeper server.
    """
    return cloud_config({
        'drivescale': {
            'zk_servers': [dms_ip],
        }
    })


adapter_user_data = client_user_data
server_user_data = client_user_data


def get_singleton(x):
    it = iter(x)
    try:
        val = next(it)
    except StopIteration:
        assert False, 'empty sequence, not singleton'
    try:
        next(it)
    except StopIteration:
        return val
    else:
        assert False, 'sequence length > 1, not singleton'


class Fatal(Exception):
    pass


def fatal(s):
    raise Fatal(s)


Image = namedtuple('Image',
                   'image_id name version role platform creation expiration')


class DriveScaleImages(object):
    """search for DriveScale shared AMIs"""

    def __init__(self, ec2):
        self.ec2 = ec2
        self._images = None

    @property
    def images(self):
        if self._images is not None:
            return self._images

        # Images are named
        # drivescale/poc/<version>/<role>/<platform>/<creation>...  and
        # composer images have an additional /<expiry> indicating date of
        # expiration of included license.
        response = self.ec2.describe_images(Owners=[DRIVESCALE_IMAGES_ACCOUNT])
        images = []
        for image in response['Images']:
            parts = image['Name'].split('/')
            if parts[0:2] != ['drivescale', 'poc'] or len(parts) < 6:
                continue
            version, role, platform, creation = parts[2:6]
            if role == 'composer':
                if len(parts) < 7:
                    continue
                expiration = parts[6]
            else:
                expiration = None
            images.append(Image(image['ImageId'], image['Name'],
                                version, role, platform,
                                creation, expiration))
        self._images = images
        return images

    def preferred_image(self, role):
        suitable = [x for x in self.images if x.role == role]
        suitable.sort(key=DriveScaleImages._sort_key)
        if not suitable:
            return None
        return suitable[-1].image_id

    @staticmethod
    def _parse_version(s):
        # Convert string version to comparable interpretation.  Use
        # packaging.version_parse if available, else poor man's substitute.
        if packaging_version_parse is not None:
            return packaging_version_parse(s)

        def segment(x):
            m = re.match(r'(\d*)(.*)', x)
            return [int(m.group(1)), m.group(2)]

        parts = s.split('.')
        return [x for p in parts for x in segment(p)]

    @staticmethod
    def _sort_key(image):
        return (DriveScaleImages._parse_version(image.version),
                image.platform, image.expiration, image.creation)

    def have_all_images(self):
        return all(self.preferred_image(role) is not None
                   for role in ('composer', 'server', 'adapter'))


def tcp_permission(cidr, port, port_high=None):
    """format a tcp network permission

    Formats a network permission allowing access to the specified CIDR block(s)
    and given TCP port range.  The result is suitable to be included in
    IpPermissions in authorize_security_group_*.  port None specified all
    ports.  If port_high is specified, the range from port to port_high is
    specified; otherwise only a single port is specified.  cidr must be a
    string describing a CIDR block (including the /) or an iterable of same."""
    if port is None:
        port = 0
        port_high = 65535
    elif port_high is None:
        port_high = port

    if isinstance(cidr, str):
        cidr = [cidr]

    return {
        'IpProtocol': 'tcp',
        'FromPort': port,
        'ToPort': port_high,
        'IpRanges': [{'CidrIp': c} for c in cidr]
    }


def one_filter(name, values):
    """filter for name with accepted values"""
    return {'Name': name, 'Values': values}


def simple_filter(name, value):
    """filter for name with one accepted value"""
    return one_filter(name, [value])


def simple_tag_filter(tag, value):
    """filter for tag matching"""
    return simple_filter('tag:' + tag, value)


def vpc_filter(vpc_id):
    """filter for matching VPC id"""
    return simple_filter('vpc-id', vpc_id)


def tag_value(taggable, name):
    """value of a given tag for some taggable object; None if no match"""
    for kv in taggable.get('Tags', []):
        if kv.get('Key') == name:
            return kv.get('Value')
    return None


def one_tag(key, value):
    return {'Key': key, 'Value': value}


def boto_error_code(client_error):
    """fish error code out of botocore.ClientError (string)"""
    return client_error.response['Error']['Code']


def volume_active_attachment(volume):
    """instance ID and device of active attachment for a volume"""
    attachments = volume.get('Attachments', [])
    for a in attachments:
        if a.get('State') == 'attached':
            return a.get('InstanceId'), a.get('Device')
    return None, None


class DriveScaleDomain(object):
    """manages one DriveScale management domain in one VPC"""

    def __init__(self, name, vpc_id, external_cidr=None, key_pair=None):
        self.name = name
        self.ec2 = boto3.client('ec2')
        self.images = DriveScaleImages(self.ec2)

        self.vpc_id = self._find_vpc(vpc_id)
        self.zone = REGION + 'a'

        self.subnet_id = self._find_subnet(self.vpc_id, self.zone)

        self._key_pair = key_pair

        # Prefix used for things associated with us by name.
        self._prefix = 'drivescale-domain-%s-' % self.name
        self._external_cidr = external_cidr

        self._sgs = {}
        self._dms_public_ip = None
        self._dms_private_ip = None
        self._key_pair_verified = False

    def _find_vpc(self, vpc):
        if vpc is None or vpc == 'default':
            search = {'Filters': [simple_filter('isDefault', 'true')]}
            desc = 'default VPC'
        elif vpc.startswith('vpc-'):
            search = {'VpcId': vpc}
            desc = 'VPC with id %s' % vpc
        else:
            fatal('Invalid VPC id %s', vpc)

        response = self.ec2.describe_vpcs(**search)
        vpcs = response['Vpcs']
        if len(vpcs) > 1:
            # Should be impossible when searching for default or by id.
            fatal('Found multiple %ss.' % desc)
        elif not vpcs:
            fatal('Found no %s.' % desc)
        return vpcs[0]['VpcId']

    def _find_subnet(self, vpc_id, zone):
        response = self.ec2.describe_subnets(
            Filters=[vpc_filter(vpc_id),
                     simple_filter('availability-zone', zone)])
        subnets = response['Subnets']
        if len(subnets) == 1:
            return subnets[0]['SubnetId']
        for subnet in subnets:
            if subnet.get('DefaultForAz'):
                return subnet['SubnetId']
        return None  # No or ambiguous match.

    def key_pair_exists(self):
        """true if the key pair for the domain exists"""
        try:
            response = self.ec2.describe_key_pairs(KeyNames=[self._key_pair])
        except ClientError as e:
            if boto_error_code(e) == KEY_PAIR_NOT_FOUND_ERROR:
                response = {'KeyPairs': []}
            else:
                raise
        if response['KeyPairs']:
            self._key_pair_verified = True
            return True
        else:
            return False

    def key_pair(self):
        """key pair for the domain if it exists

        raises RuntimeError if it does not"""
        if not self._key_pair_verified:
            if not self.key_pair_exists():
                raise RuntimeError('keypair %s does not exist'
                                   % self._key_pair)
        return self._key_pair

    def _pname(self, name):
        """prefix a name with the domain name to make it unique"""
        return self._prefix + name

    def external_cidr(self):
        """external CIDR range for access to SSH and HTTPS

        If no CIDR range has been specified, uses checkip.amazonaws.com to
        determine the local IP as seen by AWS, and uses that single IP."""
        if self._external_cidr is None:
            # Default to our IP as seen by AWS.  checkip.amazonaws.com is an
            # IPv4-only service, so we will only deal with v4 addresses.
            response = urlopen('https://checkip.amazonaws.com/')
            ip = response.read().strip()
            if re.match(rb'(\d{1,3}\.){3}\d{1,3}$', ip):
                self._external_cidr = ip.decode('ascii') + '/32'
            else:
                fatal("%s from checkip.amazonaws.com isn't an IPv4 address"
                      % ip)

        return self._external_cidr

    def create_instances(self, image_id, instance_type, security_groups,
                         role, user_data, count=1):
        if self.subnet_id is None:
            fatal("Cannot determine subnet in which to allocate instances.")
        tag_spec = [{
            'ResourceType': 'instance',
            'Tags': [
                one_tag(DOMAIN_TAG, self.name),
                one_tag(ROLE_TAG, role),
                one_tag(NAME_TAG, self._pname(role)),
            ],
        }]
        network_interfaces = [
            {
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': True,
                'SubnetId': self.subnet_id,
                'Groups': security_groups,
            }
        ]
        response = self.ec2.run_instances(
            ImageId=image_id, InstanceType=instance_type,
            KeyName=self.key_pair(), MaxCount=count, MinCount=count,
            TagSpecifications=tag_spec, UserData=user_data,
            NetworkInterfaces=network_interfaces,
            Placement={'AvailabilityZone': self.zone})
        for inst in response['Instances']:
            print('Started', instance_type, role, 'instance',
                  inst['InstanceId'])
        return response['Instances']

    def delete_instances(self, role=None):
        """terminate domain instances, or all instances in a domain

        If a role is specified, terminate all instances for the role in this
        domain.  If role is None, all instances in the domain will be
        terminated."""

        to_delete = self.list_instance_ids(role)
        for instance_id in to_delete:
            print('Terminating instance', instance_id)
        if to_delete:  # Call rejects empty InstanceIds list.
            self.ec2.terminate_instances(InstanceIds=to_delete)
        return to_delete

    def vpc_filter(self):
        return vpc_filter(self.vpc_id)

    def domain_filter(self):
        return simple_tag_filter(DOMAIN_TAG, self.name)

    def volume_vpc_filter(self):
        return simple_tag_filter(VOLUME_VPC_TAG, self.vpc_id)

    def list_instances(self, role=None):
        filters = [self.vpc_filter(), self.domain_filter(),
                   INSTANCE_NOT_TERMINATED_FILTER]
        if role is not None:
            filters.append(simple_tag_filter(ROLE_TAG, role))
        response = self.ec2.describe_instances(Filters=filters)
        return [inst for resv in response['Reservations']
                for inst in resv['Instances']]

    def list_instance_ids(self, *args, **kwargs):
        return [x['InstanceId'] for x in self.list_instances(*args, **kwargs)]

    def _find_or_create_security_group(self, name):
        pname = self._pname(name)
        response = self.ec2.describe_security_groups(
            Filters=[self.vpc_filter(), simple_filter('group-name', pname)])
        sgs = response['SecurityGroups']
        if not sgs:
            sg = self.ec2.create_security_group(
                GroupName=pname, Description=pname, VpcId=self.vpc_id)
            print('Created security group', sg['GroupId'], pname)
            return sg['GroupId'], False
        if len(sgs) != 1:
            # This should not be possible, as duplicate names are not allowed
            # within a VPC.  If it happens it must mean we botched the filter.
            raise RuntimeError('multiple security groups for name %s'
                               % pname)
        sg = sgs[0]
        sg_id = sg['GroupId']
        is_initialized = tag_value(sg, INITIALIZED_TAG) is not None
        return sg_id, is_initialized

    def _mark_sg_initialized(self, sg_id, version=1):
        # The intent is that 1 here means initialized with the first version of
        # required permissions for this group, i.e. in the future there might
        # be 2, and we will have recorded which permissions would need to be
        # added or removed when seeing an old version.
        self.ec2.create_tags(Resources=[sg_id],
                             Tags=[one_tag(INITIALIZED_TAG, str(version))])

    def _ensure_ingress_permissions(self, sg_id, permissions):
        try:
            self.ec2.authorize_security_group_ingress(
                GroupId=sg_id, IpPermissions=permissions)
            return
        except ClientError as e:
            # Something in the list was already present.
            if boto_error_code(e) != DUPLICATE_PERMISSION_ERROR:
                raise

        if len(permissions) == 1:
            return  # The *only* thing in the list was duplicate.  We are done.

        # Try one at a time and ignore any complaints about duplicates.
        for permission in permissions:
            try:
                self.ec2.authorized_security_group_ingress(
                    GroupId=sg_id, IpPermissions=[permission])
            except ClientError as e:
                if boto_error_code(e) != DUPLICATE_PERMISSION_ERROR:
                    raise

    def find_or_create_security_group(self, name, permissions):
        sg_id = self._sgs.get(name)
        if sg_id is None:
            sg_id, is_initialized = self._find_or_create_security_group(name)
            if not is_initialized:
                self._ensure_ingress_permissions(sg_id, permissions)
                self._mark_sg_initialized(sg_id)
            self._sgs[name] = sg_id
        return sg_id

    def list_security_groups(self):
        response = self.ec2.describe_security_groups(
            Filters=[self.vpc_filter(),
                     simple_filter('group-name', self._prefix + '*')])
        return response['SecurityGroups']

    def delete_security_groups(self):
        for sg in self.list_security_groups():
            print('Deleting security group', sg['GroupId'],
                  sg.get('GroupName', ''))
            self.ec2.delete_security_group(GroupId=sg['GroupId'])

    def external_ssh_sg_id(self):
        return self.find_or_create_security_group(
            'external-ssh', [tcp_permission(self.external_cidr(), 22)])

    def external_https_sg_id(self):
        return self.find_or_create_security_group(
            'external-https', [tcp_permission(self.external_cidr(), 443)])

    def internal_sg_id(self):
        name = 'internal'
        sg_id = self._sgs.get(name)
        if sg_id is None:
            sg_id, is_initialized = self._find_or_create_security_group(name)
            if not is_initialized:
                response = self.ec2.describe_security_groups(GroupIds=[sg_id])
                sg = get_singleton(response['SecurityGroups'])
                owner_id = sg['OwnerId']
                # The custom, variable IpPermissions is why we don't call
                # find_or_create_security_group.
                permissions = [{
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [{'GroupId': sg_id,
                                          'UserId': owner_id}]
                }]
                self._ensure_ingress_permissions(sg_id, permissions)
                self._mark_sg_initialized(sg_id)
            self._sgs[name] = sg_id
        return sg_id

    def composer_sgs(self):
        return [self.external_ssh_sg_id(), self.external_https_sg_id(),
                self.internal_sg_id()]

    def adapter_sgs(self):
        return [self.external_ssh_sg_id(), self.internal_sg_id()]

    def server_sgs(self):
        return [self.external_ssh_sg_id(), self.internal_sg_id()]

    def find_dms(self):
        instances = self.list_instances(COMPOSER_ROLE)
        if not instances:
            return None
        if len(instances) > 1:
            raise RuntimeError(
                'multiple DMS instances found: %s' %
                ' '.join(x.get('InstanceId') for x in instances))

        dms_instance = instances[0]
        self._cache_dms_ips(dms_instance)
        return dms_instance

    def find_or_create_dms(self):
        dms_instance = self.find_dms()
        if dms_instance is None:
            instances = self.create_instances(
                self.images.preferred_image(COMPOSER_ROLE), 't2.small',
                self.composer_sgs(), COMPOSER_ROLE, dms_user_data())
            dms_instance = get_singleton(instances)
            self._cache_dms_ips(dms_instance)
        return dms_instance

    def dms_private_ip(self):
        if self._dms_private_ip is None:
            self.find_dms()
        return self._dms_private_ip

    def dms_public_ip(self):
        if self._dms_public_ip is None:
            self.find_dms()
        return self._dms_public_ip

    def _cache_dms_ips(self, dms_instance):
        self._dms_public_ip = dms_instance.get('PublicIpAddress')
        self._dms_private_ip = dms_instance.get('PrivateIpAddress')

    def find_instances(self, filters):
        filters += [self.vpc_filter(), self.domain_filter(),
                    INSTANCE_NOT_TERMINATED_FILTER]
        response = self.ec2.describe_instances(Filters=filters)
        return [inst for resv in response['Reservation']
                for inst in resv['Instances']]

    def _volume_device_seq(self):
        for x in 'abcdefghijklmnopqrstuvwxyz':
            yield '/dev/xvdb' + x

    def create_adapters(self, count, drives_per_adapter, gb_per_drive):
        if count < 1:
            return

        dms_private_ip = self.dms_private_ip()
        adapters = self.create_instances(
            self.images.preferred_image(ADAPTER_ROLE), 't2.micro',
            self.adapter_sgs(), ADAPTER_ROLE,
            server_user_data(dms_private_ip),
            count=count)

        # Ensures that we don't make more volumes than we know how to attach.
        drives_per_adapter = len(list(zip(range(drives_per_adapter),
                                          self._volume_device_seq())))

        volume_tag_spec = [{
            'ResourceType': 'volume',
            'Tags': [
                one_tag(VOLUME_VPC_TAG, self.vpc_id),
                one_tag(DOMAIN_TAG, self.name),
                one_tag(NAME_TAG, self._pname('volume')),
            ],
        }]
        volumes_to_attach = {}
        for instance in adapters:
            volumes = []
            az = instance['Placement']['AvailabilityZone']
            instance_id = instance['InstanceId']
            for x in range(drives_per_adapter):
                response = self.ec2.create_volume(
                    AvailabilityZone=az, VolumeType='gp2', Size=gb_per_drive,
                    TagSpecifications=volume_tag_spec)
                volume_id = response['VolumeId']
                print('Created', gb_per_drive, 'GB volume for adapter',
                      instance_id)
                volumes.append(volume_id)
            volumes_to_attach[instance_id] = volumes
        all_volumes = [vol for vl in volumes_to_attach.values() for vol in vl]

        waiter = self.ec2.get_waiter('instance_running')
        print('Waiting for newly created adapters to be running')
        waiter.wait(InstanceIds=[x['InstanceId'] for x in adapters])

        waiter = self.ec2.get_waiter('volume_available')
        print('Waiting for newly created volumes to be available')
        waiter.wait(VolumeIds=all_volumes)

        for instance_id, volumes in volumes_to_attach.items():
            for volume_id, device in zip(volumes, self._volume_device_seq()):
                print('Attaching volume', volume_id, 'to', instance_id, 'as',
                      device)
                self.ec2.attach_volume(InstanceId=instance_id,
                                       VolumeId=volume_id, Device=device)

    def create_workers(self, count):
        if count < 1:
            return []
        dms_private_ip = self.dms_private_ip()
        assert dms_private_ip is not None
        workers = self.create_instances(
            self.images.preferred_image(SERVER_ROLE), 't2.micro',
            self.server_sgs(), SERVER_ROLE,
            server_user_data(dms_private_ip),
            count=count)
        return workers

    def list_volumes(self):
        response = self.ec2.describe_volumes(
            Filters=[self.volume_vpc_filter(), self.domain_filter()])
        return response['Volumes']

    def delete_volumes(self):
        volumes = self.list_volumes()
        for volume in self.list_volumes():
            print('Deleting volume', volume['VolumeId'])
            self.ec2.delete_volume(VolumeId=volume['VolumeId'])
        return [x['VolumeId'] for x in volumes]


def domain_for_args(args):
    return DriveScaleDomain(args.name, vpc_id=None,
                            key_pair=args.key_pair,
                            external_cidr=args.external_cidr)


def create_or_expand_domain(args):
    """Allocate resources for a DriveScale domain.

    If there is not a management server for the domain, one is created.
    Create instances for the specified number of servers and adapters.  Creates
    and attaches volumes for each created adapter instance.  Creates security
    groups as required.

    This command can be used either to create or to expand a domain."""
    domain = domain_for_args(args)
    print('Allocating instances in', domain.name, 'in', domain.vpc_id)
    print()

    dms_instance = domain.find_dms()
    if ((dms_instance is None or args.adapters or args.servers)
            and not domain.key_pair_exists()):
        print('ERROR: The key pair', args.key_pair, 'does not exist.')
        print('New instances cannot be created.')
        return 1

    if not domain.images.have_all_images():
        print('ERROR: Cannot find DriveScale AMIs.  You may have registered')
        print('an incorrect AWS account ID or your trial period may have')
        print('expired.')
        return 1

    dms_instance = domain.find_or_create_dms()
    servers = domain.create_workers(args.servers)

    domain.create_adapters(args.adapters, args.drives_per_adapter,
                           args.gb_per_drive)

    wait_instances = [x['InstanceId'] for x in servers]
    if dms_instance['State']['Name'] == 'pending':
        wait_instances.append(dms_instance['InstanceId'])

    if wait_instances:
        print('Waiting for created instances to be running')
        print('   ', *wait_instances)
        waiter = domain.ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=wait_instances)
        print()

    dms_ip = domain.dms_public_ip()
    if dms_ip:
        print()
        print('Management console URL:')
        print('    https://%s/' % dms_ip)
        print()


def delete_domain(args):
    """Delete all resources in a DriveScale domain.

    Deletes instances, volumes, and security groups associated with the named
    DriveScale domain."""

    domain = domain_for_args(args)
    print('Deleting domain', domain.name, 'in', domain.vpc_id)
    deleted_ids = domain.delete_instances()
    if deleted_ids:
        print('Waiting for instances to complete termination')
        waiter = domain.ec2.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=deleted_ids)
    domain.delete_volumes()
    domain.delete_security_groups()


def _empty_none(xs):
    """print placeholder marker for an empty list"""
    if not xs:
        print('    (None.)')


def show_domain(args):
    """Display all resources used by a domain.

    Includes instances, volumes, and security groups.
    """

    domain = domain_for_args(args)
    print('Contents of domain', domain.name, 'in', domain.vpc_id)
    print()

    by_role = {role: [] for role in ALL_ROLES}
    instances = domain.list_instances()
    for instance in instances:
        role = tag_value(instance, ROLE_TAG)
        brl = by_role.get(role)
        if brl is None:
            by_role.setdefault('unknown', []).append(instance)
        else:
            brl.append(instance)

    print_roles = list(ALL_ROLES)
    if 'unknown' in by_role:
        print_roles.append('unknown')

    for role in print_roles:
        print('Instances for', role, 'role:')
        instances = by_role[role]
        _empty_none(instances)
        if instances:
            for instance in instances:
                print('    %s %s %s %s'
                      % (instance['InstanceId'], instance['InstanceType'],
                         instance.get('PrivateIpAddress') or '-',
                         instance.get('PublicIpAddress') or '-'))
        print()

    volumes = domain.list_volumes()
    volumes.sort(key=volume_active_attachment)
    print('Volumes:')
    _empty_none(volumes)
    for v in volumes:
        instance_id, device = volume_active_attachment(v)
        print('    %s %s %dGB %s %s' % (v['VolumeId'], v['VolumeType'],
                                        v['Size'], instance_id or '-',
                                        device or '-'))
    print()

    print('Security groups:')
    sgs = domain.list_security_groups()
    _empty_none(sgs)
    for sg in sgs:
        print('    %s %s' % (sg['GroupId'], sg['GroupName']))

    dms_ip = domain.dms_public_ip()
    if dms_ip:
        print()
        print('Management console URL:')
        print('    https://%s/' % dms_ip)
        print()


def list_domains(args):
    """Show a summary of all DriveScale domains.

    Shows all domains in all VPCs along with a summary of resources used."""
    ec2 = boto3.client('ec2')

    instance_count = defaultdict(int)
    volume_count = defaultdict(int)
    volume_total_size = defaultdict(int)

    response = ec2.describe_security_groups(
        Filters=[simple_filter('group-name', 'drivescale-domain-')])
    for sg in response['SecurityGroups']:
        name = sg['GroupName']
        parts = name.split('-')
        if parts[-1] == 'internal':
            domain = '-'.join(parts[2:-1])
        else:
            domain = '-'.join(parts[2:-2])
        instance_count[(sg['VpcId'], domain)] += 0

    any_domain_filter = simple_tag_filter(DOMAIN_TAG, '*')

    response = ec2.describe_instances(
        Filters=[any_domain_filter, INSTANCE_NOT_TERMINATED_FILTER])
    for resv in response['Reservations']:
        for inst in resv['Instances']:
            domain = tag_value(inst, DOMAIN_TAG)
            vpc_id = inst.get('VpcId')
            if vpc_id is not None:
                # It is missing on terminated instances, which we are
                # excluding--maybe in other cases too?
                instance_count[(inst['VpcId'], domain)] += 1

    response = ec2.describe_volumes(Filters=[any_domain_filter])
    for volume in response['Volumes']:
        domain = tag_value(volume, DOMAIN_TAG)
        vpc_id = tag_value(volume, VOLUME_VPC_TAG)
        volume_count[(vpc_id, domain)] += 1
        volume_total_size[(vpc_id, domain)] += volume['Size']

    domains = sorted(instance_count.keys())

    print("Domains:")
    _empty_none(domains)
    for domain in domains:
        vpc_id, name = domain
        instances = instance_count.get(domain, 0)
        volumes = volume_count.get(domain, 0)
        size = volume_total_size.get(domain, 0)

        print(vpc_id, name, instances, 'instance(s)', volumes,
              'volume(s) totalling', size, 'GB')


def list_images(args):
    ec2 = boto3.client('ec2')
    images = DriveScaleImages(ec2)
    print('Best available DriveScale images:')
    for role in ALL_ROLES:
        image = images.preferred_image(role)
        if image is None:
            print(role, '(none available)')
        else:
            print(role, image.image_id, image.name)


def create_vpc(args):
    """Create a new VPC similar to the default VPC created by AWS.

    Create a new VPC with internal CIDR range 172.30.0.0/16 (the default VPC
    is 172.31/16; it is not actually necessary that they be disjoint.)
    Attaches an internet gateway to the VPC and uses it as the default route.
    Creates a /20 subnet in each availability zone."""
    print('Creating a new VPC.')
    print()

    cidr_block = ipaddress.ip_network('172.30.0.0/16')

    ec2 = boto3.client('ec2')
    response = ec2.create_vpc(CidrBlock=str(cidr_block))
    vpc_id = response['Vpc']['VpcId']
    print('Created VPC', vpc_id)

    # self.ec2.create_tags(Resources=[self.vpcid], Tags=tag_list)
    response = ec2.create_internet_gateway()
    igw_id = response['InternetGateway']['InternetGatewayId']
    print('Created internet gateway', igw_id)

    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    response = ec2.describe_route_tables(Filters=[vpc_filter(vpc_id)])
    # There will only be exactly one route table in our newly-created VPC.
    rt_id = response['RouteTables'][0]['RouteTableId']
    ec2.create_route(DestinationCidrBlock='0.0.0.0/0',
                     RouteTableId=rt_id, GatewayId=igw_id)

    response = ec2.describe_availability_zones()
    for az, subnet_cidr in zip(response['AvailabilityZones'],
                               cidr_block.subnets(20 - cidr_block.prefixlen)):
        if az['State'] == 'available':
            az_name = az['ZoneName']
            response = ec2.create_subnet(AvailabilityZone=az['ZoneName'],
                                         VpcId=vpc_id,
                                         CidrBlock=str(subnet_cidr))
            subnet_id = response['Subnet']['SubnetId']
            ec2.modify_subnet_attribute(SubnetId=subnet_id,
                                        MapPublicIpOnLaunch=True)
            print('Created subnet', subnet_id,
                  'as', subnet_cidr, 'in', az_name)


def delete_vpc(args):
    """Deletes a VPC.

    Deletes a VPC.  Only designed to delete VPCs as created by create_vpc, but
    may work on other VPCs.  Also deletes attached subnets and internet
    gateways.  Scans for associated instances and generates and error message
    if there are any."""
    vpc_id = args.vpc_id
    our_vpc_filter = vpc_filter(vpc_id)

    ec2 = boto3.client('ec2')

    response = ec2.describe_instances(Filters=[our_vpc_filter,
                                               INSTANCE_NOT_TERMINATED_FILTER])
    if any(r['Instances'] for r in response['Reservations']):
        print('Will not delete VPC', vpc_id, 'with active instances.')
        # The overall deletion process wouldn't succeed anyway, but we might do
        # some damage like removing some currently-unused subnets.
        return 1

    print('Deleting VPC', vpc_id,
          'and associated subnets and internet gateways.')
    print()

    for s in ec2.describe_subnets(Filters=[our_vpc_filter])['Subnets']:
        subnet_id = s['SubnetId']
        print('Deleting subnet', subnet_id)
        ec2.delete_subnet(SubnetId=subnet_id)

    attached_filter = [simple_filter('attachment.vpc-id', vpc_id)]
    response = ec2.describe_internet_gateways(Filters=attached_filter)
    for igw in response['InternetGateways']:
        igw_id = igw['InternetGatewayId']
        print('Detaching and deleting internet gateway', igw_id)
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2.delete_internet_gateway(InternetGatewayId=igw_id)

    print('Deleting VPC', vpc_id)
    ec2.delete_vpc(VpcId=vpc_id)


def key_pair_exists(ec2):
    try:
        response = ec2.describe_key_pairs(KeyNames=[DEFAULT_KEY_PAIR])
    except ClientError as e:
        if boto_error_code(e) == 'InvalidKeyPair.NotFound':
            return False
        raise
    return bool(response.get('KeyPairs'))


def _notify_default_key_pair_exists():
    print('Already have a default DriveScale key pair', DEFAULT_KEY_PAIR)
    print('If you wish to replace this key pair, you may use the AWS')
    print('console to delete the pair and rerun this command.')


def create_default_key_pair(args):
    """Create a key pair for use with DriveScale instances.

    Creates a new key pair named drivescale-default, saves the private key
    material, and reports the path of the file containing the key."""
    ec2 = boto3.client('ec2')

    try:
        response = ec2.create_key_pair(KeyName=DEFAULT_KEY_PAIR)
    except ClientError as e:
        if boto_error_code(e) == DUPLICATE_KEY_PAIR_ERROR:
            print('DriveScale key pair', DEFAULT_KEY_PAIR, 'already exists.')
            print('To replace the key pair, use the AWS console to delete the')
            print('pair and then rerun this command.')
            return
        raise

    try:
        os.makedirs(expanduser('~/.ssh'))
    except Exception:
        pass

    key_contents = response['KeyMaterial']
    written_to = None
    try:
        for tries in range(16):
            path = expanduser('~/.ssh/id_drivescale_aws_default_'
                              + ''.join('%02x' % x for x in os.urandom(4)))
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                continue
            except Exception:
                break
            with os.fdopen(fd, 'w') as f:
                f.write(key_contents)
            written_to = path
            break

    finally:
        if written_to:
            print('Wrote private key for new key pair', DEFAULT_KEY_PAIR,
                  'to', written_to)
        else:
            print('Unable to write private key for new key pair',
                  DEFAULT_KEY_PAIR)
            print('Contents are:')
            print(key_contents)


def add_aws_arguments(parser):
    group = parser.add_argument_group('AWS client options')
    # group.add_argument('--region', help='AWS region to use')
    group.add_argument('--profile', help='profile for credentials')


def set_boto3_default_session(args):
    boto3.setup_default_session(profile_name=args.profile,
                                region_name=REGION)
    #                             region_name=args.region)


CREDENTIALS_COMMON_TEXT = """\
\x20
    [default]
    aws_access_key_id=XXXXXXXXXXXXXXXXXXXX
    aws_secret_access_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
\x20
They can be retrieved from the "My Security Credentials" section of your
account in the AWS console, for root accounts or users that have console
access.
\x20
This file can also be generated by the interactive configure command of the AWS
CLI (https://aws.amazon.com/cli/).
\x20
See
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html
for more details about configuration and credentials for the AWS client library
boto3 used by this tool.
"""

# RawDescriptionHelpFormatter collapses consecutive empty lines.  Put a space
# on one of them so it will be preserved, but express as \x20 so that there
# isn't trailing whitespace in the source.
USAGE_EPILOG = """
Detailed help for each command is available with command --help.

\x20
WARNING

The domains created by this script are intended for transient, demonstration
purposes.  The management services are created without redundancy and if the
volumes associated with the management services fail data can be unrecoverably
lost.  In particular if the encryption feature is enabled and the volume for
the management service (composer instance) fails or is deleted, the encryption
keys for all encrypted volumes will be unrecoverably lost and the data on the
drives lost.

\x20
PREREQUISITES

An appropriate aws_acess_key_id and aws_secret_access_key must be available
to the boto3 AWS API client library.  Typically this means placing them in
~/.aws/credentials:
""" + CREDENTIALS_COMMON_TEXT + """\

\x20
EXAMPLE USAGE

Create a key pair that will be used for instances created by this script:

    python3 aws_poc.py create-key-pair

Create a small domain named 'sample' with two servers and one adapter with two
volumes, each one gigabyte.  This will also create the management server
instance and report the public URL.

    python3 aws_poc.py create sample 2 1 2 1

Now visit the URL given by the create command, perform the setup procedure,
etc.

Display the resources in the domain:

    python3 aws_poc.py show sample

Among other things, this reports the public IP addresses of the created server
instances, which are accessible with the SSH private key created by create-key.
(For the Ubuntu-based server images, the user name is ubuntu.)

When finished, destroy the domain including all volumes, instances, and
created security groups:

    python3 aws_poc.py delete sample

\x20
GUI HTTPS ACCESS

The composer instance for each domain provides a management API and GUI over
HTTPS.  When the instance is created a security group
drivescale-domain-<name>-external-https is assigned to the instance.  By
default this group allows HTTPS access only to the IP address on which this
script is run, as seen by checkip.amazonaws.com.  If given the value of the
--external-cidr option is used instead.  This option may be required for
reliable access if using a NAT-based firewall with multiple external addresses.

The security group can also be edited directly with the AWS console.

\x20
INSTANCE SSH ACCESS

Every instance is associated with a security group
drivescale-domain-<name>-external-ssh, which allows external SSH access to the
instance.  The associated IP or IP range is chosen by the same policy as for
HTTPS access.

If the --key-pair option is given, the named key pair is used for any instance
creation and the associated private key may be used for administrative user SSH
login.  If the --key-pair option is not given, the drivescale-default key pair
will be used.  If the named key pair does not exist, instance creation will
not be attempted.

"""


def main():
    parser = argparse.ArgumentParser(
        description='manage DriveScale domains on AWS',
        epilog=USAGE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_aws_arguments(parser)

    def show_help(args):
        parser.print_usage()
        print()
        print('For detailed usage:  aws_poc.py -h')

    # Prints usage message if no command specified.
    parser.set_defaults(func=show_help)

    parser.set_defaults(key_pair=DEFAULT_KEY_PAIR,
                        external_cidr=None)

    subparsers = parser.add_subparsers(help='action')

    def command_parser(name, func, help):
        subparser = subparsers.add_parser(
            name, help=help,
            description=inspect.getdoc(func) or help,
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        subparser.set_defaults(func=func)
        return subparser

    parser_create = command_parser(
        'create', create_or_expand_domain,
        help='allocate DriveScale domain resources')
    parser_create.add_argument(
        '--external-access', dest='external_cidr',
        help="CIDR block from which to allow SSH and HTTPS access. "
        "Default is the IP address of this machine as see by AWS.")
    parser_create.add_argument(
        '--key-pair', dest='key_pair',
        help="name of key pair for newly created instances",
        default=DEFAULT_KEY_PAIR)
    parser_create.add_argument('name', help='domain identifier')
    parser_create.add_argument('servers', type=int,
                               help='number of servers to allocate')
    parser_create.add_argument('adapters', type=int,
                               help='number of adapters to allocate')
    parser_create.add_argument('drives_per_adapter', type=int,
                               help='number of drives per adapter')
    parser_create.add_argument('gb_per_drive', type=int,
                               help='size of each drive in gigabytes')

    parser_delete = command_parser(
        'delete', delete_domain,
        help='delete DriveScale domain resources')
    parser_delete.add_argument('name', type=str, help='domain identifier')

    parser_list = command_parser(
        'show', show_domain,
        help='display resources in a DriveScale domain')
    parser_list.add_argument('name', type=str, help='domain identifier')

    command_parser('list', list_domains,
                   help='list existing domains')

    command_parser('create-vpc', create_vpc,
                   help='create a new VPC suitable for use with the script')

    parser_delete_vpc = command_parser(
        'delete-vpc', delete_vpc,
        help='delete a VPC')
    parser_delete_vpc.add_argument('vpc_id')

    command_parser(
        'create-key-pair', create_default_key_pair,
        help='create a key pair for instances in DriveScale domains')

    command_parser('images', list_images, help='show AMIs that will be used')

    args = parser.parse_args()
    set_boto3_default_session(args)

    try:
        rv = args.func(args)
    except Fatal as e:
        print(str(e))
        print()
        print('Aborting.')
        rv = 1
    except NoCredentialsError:
        print("""\
Unable to locate AWS API credentials.

These consist of the aws_access_key_id and aws_secret_access_key and are
typically placed in ~/.aws/credentials:
""" + CREDENTIALS_COMMON_TEXT)
        print("Cannot continue without AWS credentials.  Exiting.")
        rv = 1
    if rv:
        sys.exit(rv)


if __name__ == '__main__':
    main()
