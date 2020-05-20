import sys  # nopep8
sys.path.insert(1, '/var/vmwareStaging/modules')  # nopep8
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import json
import ssl
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl
import time
import re
import requests
import random
import string
from datetime import timedelta, datetime
import jitsi
import snapshot
import disk


# from django.http import JsonResponse


class VcenterApiWrapper:
    # TODO install pyvmomy module
    def __init__(self, host, user, password, clone=False):
        self.virtual_machines_list = []
        self.esx_host_list = []
        self.resource_pools_list = []
        self.datacenters = []
        self.datastores = []
        self.this_object_reference = None
        self.session = self.__get_session(host, user, password)
        if(clone):
            # self.__get_all_vms()
            # self.__get_all_hosts()
            self.__get_all_resource_pools()
            self.__get_all_datacenters()
            self.__get_all_datastores()
        return

    def __get_session(self, host, user, password):
        # create connection
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE
        try:
            print("trying to connect...")
            api_session = SmartConnect(
                host=host, user=user, pwd=password, sslContext=context)
            print("obtained session, success!")
            return api_session
        except Exception as err:
            print(err)
            sys.exit(1)

    def disconect(self):
        Disconnect(self.session)
        return True

    def __get_all_hosts(self):
        # Loop to each parent entity recursively and
        # populate the list 'vcenter_vms_list' with each host details as a dict
        container = self.session.content.viewManager.CreateContainerView(self.session.content.rootFolder,
                                                                         [vim.HostSystem], True)
        for host in container.view:
            self.esx_host_list.append({'name': host.name, 'reference': host})

    def __get_all_vms(self):
        # Loop to each parent entity recursively and
        # populate the list 'vcenter_vms_list' with each vm details as a dict

        global vms_list
        vms_list = []
        for datacenters in self.session.content.rootFolder.childEntity:
            self.__recursive_traverse_entities(datacenters)
        for vm in vms_list:
            self.virtual_machines_list.append({'name': vm.summary.config.name,
                                               'uuid': vm.summary.config.uuid,
                                               'reference': vm,
                                               'ip': vm.summary.guest.ipAddress})
        return

    # def delete_vm_1(self,testvm):
    #     VM =self.session.content.searchIndex.FindByUuid(None, testvm,True,False)
    #     if(VM):
    #         TASK = VM.PowerOnVM_Task()
    #         return VM
    def getTemplateByUuid(self, uuid):
        VM = self.session.content.searchIndex.FindByUuid(
            None, uuid, True, False)
        return VM

    def __get_all_resource_pools(self):
        container = self.session.content.viewManager.CreateContainerView(self.session.content.rootFolder,
                                                                         [vim.ResourcePool], True)
        for resource_pool in container.view:
            self.resource_pools_list.append({'entity': resource_pool.name,
                                             'owner': resource_pool.owner.name,
                                             'parent': resource_pool.parent.name,
                                             'reference': resource_pool})

    def __get_all_datacenters(self):
        container = self.session.content.viewManager.CreateContainerView(self.session.content.rootFolder,
                                                                         [vim.Datacenter], True)
        for datacenter in container.view:
            self.datacenters.append(
                {'name': datacenter.name, 'reference': datacenter})

    def __get_all_datastores(self):
        container = self.session.content.viewManager.CreateContainerView(self.session.content.rootFolder,
                                                                         [vim.Datastore], True)
        for datastore in container.view:
            self.datastores.append({'name': datastore.name, 'reference': datastore,
                                    'freeSpaceGB': int(datastore.info.freeSpace / 1024 / 1024 / 1024)})

    def __recursive_traverse_entities(self, root_folder, depth=1):
        # Traverse all vms entities from vcenter recursively.
        max_depth = 16
        if depth > max_depth:
            print("reached max recursive depth!")
            return
        object_type = root_folder.__class__.__name__

        if object_type == "vim.Datacenter":
            for _entity in root_folder.hostFolder.childEntity:
                self.__recursive_traverse_entities(_entity, depth + 1)
                if hasattr(_entity, "snapshot"):
                    vms_list.append(_entity)
            for _entity in root_folder.vmFolder.childEntity:
                self.__recursive_traverse_entities(_entity, depth + 1)
                if hasattr(_entity, "snapshot"):
                    vms_list.append(_entity)
            return

        if object_type == "vim.ClusterComputeResource":
            for _entity in root_folder.host:
                self.__recursive_traverse_entities(_entity, depth + 1)
                if hasattr(_entity, "snapshot"):
                    vms_list.append(_entity)
            return

        if object_type == "vim.Folder":
            for _entity in root_folder.childEntity:
                self.__recursive_traverse_entities(_entity, depth + 1)
                if hasattr(_entity, "snapshot"):
                    vms_list.append(_entity)
            return

        if object_type == "vim.VirtualApp":
            for _entity in root_folder.vm:
                self.__recursive_traverse_entities(_entity, depth + 1)
                if hasattr(_entity, "snapshot"):
                    vms_list.append(_entity)
            return

    def set_reference(self, r):
        # Receives the reference and set it to class var
        if not r or not self.__vm_exists(r):
            print('the reference does not exist!')
            return
        try:
            print("setting reference.")
            self.this_object_reference = r
        except Exception as err:
            print("err", err)

    def __vm_exists(self, r):
        # Verify if the specified vm exists
        # for i in self.virtual_machines_list:
        #     print(type(i['reference']))
        try:
            for vm in self.virtual_machines_list:
                if r == vm['reference']:
                    # print(r, vm['reference'])
                    return True
                    # print(r, vm['reference'])
        except Exception as err:
            print("err", err)
            return False

    def __check_reference(self):
        if self.this_object_reference is not None:
            return True
        else:
            print("invalid reference")
            return False

    def __check_for_question_pending(self, task):
        # Check to see if the VM needs to ask a question before doing a specific task

        answers = []
        vm = task.info.entity
        if vm is not None and isinstance(vm, vim.VirtualMachine):
            if vm.runtime.question is not None:
                # getting the question ID
                question_id = vm.runtime.question.id
                print("question id: %s" % question_id)

                # log the question
                print("pending question: %s" % vm.runtime.question.text)

                # iterate trough posible answers and append to answers list
                for answer in vm.runtime.question.choice.choiceInfo:
                    print("answers summary: %s with key: %s!" %
                          (answer.summary, answer.key))
                    answers.append(answer.key)

                print("trying to answer with : %s!" % answers[0])
                time.sleep(2)

                # try sending response
                try:
                    self.this_object_reference.AnswerVM(
                        question_id, answers[0])
                except vmodl.fault.InvalidArgument as e:
                    print("invalid arguments provided: %s" % e)
                    sys.exit(1)

    def get_vmware_tools_status(self):
        # get the vmware-tools status of the vm
        if self.__check_reference():
            return self.this_object_reference.summary.guest.toolsStatus
        else:
            return

    def get_power_state(self):
        # get power state of the vm
        if self.__check_reference():
            print("obtaining power state.")
            return self.this_object_reference.summary.runtime.powerState
        else:
            return False

    def power_on_vm(self):
        # power on the vm
        if self.get_power_state() == "poweredOff":
            # print(self.this_object_reference)
            task = self.this_object_reference.PowerOnVM_Task()
            state = self.__wait_task(task)
            if(state == 'success'):
                return True
            # return true
        else:
            print("vm seems to be ON or in suspended state.")
            return False

    def power_on_vm_uuid(self, r):
        task = r.PowerOnVM_Task()
        state = self.__wait_task1(task)
        if(state[0] == 'success'):
            return [True, state[1].info.entity]
        else:
            return [False, None]

    def power_off_vm_uuid(self, r):
        task = r.PowerOffVM_Task()
        state = self.__wait_task1(task)
        if(state[0] == 'success'):
            return [True, state[1].info.entity]
        else:
            return [False, None]
            # return true

    def power_off_vm(self):
        # power off the vm
        if self.get_power_state() == "poweredOn":
            task = self.this_object_reference.PowerOffVM_Task()
            self.__wait_task(task)
        else:
            print("vm seems to be OFF or in suspended state.")

    def get_resource_pool(self, name):
        # get resource pool
        container = self.session.content.viewManager.CreateContainerView(self.session.content.rootFolder,
                                                                         [vim.ResourcePool], True)
        for resource_pool in container.view:
            if resource_pool.name == name:
                return resource_pool

    def take_snapshot(self):
        # Take snapshot without memory
        task = self.this_object_reference.CreateSnapshot_Task(
            "AutoSnapshotClean", "TestAutomation", False, False)
        self.__wait_task(task)
        return

    def take_snapshot_with_memory(self):
        # Take memory snapshot with memory
        task = self.this_object_reference.CreateSnapshot_Task("AutoSnapshotCleanWithMemory",
                                                              "Automation Snapshot With Memory", True, False)
        self.__wait_task(task)
        return

    def clean_all_snapshots(self):
        # Delete all snapshots
        task = self.this_object_reference.RemoveAllSnapshots_Task()
        self.__wait_task(task)
        return

    def revert_to_current_snapshot(self):
        # Revert to current snapshot
        task = self.this_object_reference.RevertToCurrentSnapshot_Task()
        self.__wait_task(task)
        return

    def get_vm_ip(self):
        # Obtain the IP of the reference vm
        if self.__check_reference():
            if self.this_object_reference.summary.guest.ipAddress is None:
                print("IP probably null, vmware tools issue...")
                return self.this_object_reference.summary.guest.ipAddress
            else:
                return self.this_object_reference.summary.guest.ipAddress
        else:
            return

    def get_vm_ip1(self, ref):
        # Obtain the IP of the reference vm
        if ref.summary.guest.ipAddress is None:
            print("IP probably null, vmware tools issue...")
            return ref.summary.guest.ipAddress
        else:
            return ref.summary.guest.ipAddress

    def __get_task_status(self, task):
        # get task status
        state = task.info.state
        if (state == 'running' and task.info.name is not None and task.info.name.info.name != 'Destroy'
                and task.info.name.info.name != 'Relocate'):
            self.__check_for_question_pending(task)
        return state

    def __get_task_status1(self, task):
        # get task status
        state = task.info.state
        if (state == 'running' and task.info.name is not None and task.info.name.info.name != 'Destroy'
                and task.info.name.info.name != 'Relocate'):
            self.__check_for_question_pending(task)
        return [state, task]

    def __wait_task1(self, task):
        # Waits and provides updates on a vSphere task
        print(" shdvfsd", task.info.descriptionId)
        state = None
        while state not in (vim.TaskInfo.State.success, vim.TaskInfo.State.error):
            try:
                resArr = self.__get_task_status1(task)
                state = resArr[0]
                info = resArr[1]
            except vmodl.fault.ManagedObjectNotFound as e:
                print("task object has been deleted: %s" % e)
                break
        if state == "success":
            print("task success!")

        if state == "error":
            print("task reported error: %s" % str(task.info.error))
        return [state, info]

    def __wait_task(self, task):
        # Waits and provides updates on a vSphere task
        print(task.info.descriptionId)
        state = None
        while state not in (vim.TaskInfo.State.success, vim.TaskInfo.State.error):
            # print(state)
            try:
                state = self.__get_task_status1(task)
            except vmodl.fault.ManagedObjectNotFound as e:
                print("task object has been deleted: %s" % e)
                break
        if state == "success":
            print("task success!")

        if state == "error":
            print("task reported error: %s" % str(task.info.error))
        return state

    def migrate_vm(self, destination_host, target_resource_pool):
        # Migrate VMs
        # TODO Live Migration change change also the Datastore

        migrate_priority = vim.VirtualMachine.MovePriority.defaultPriority

        print("PowerON the VM")
        self.power_on_vm()

        # Live Migration change host only!
        task = self.this_object_reference.MigrateVM_Task(pool=target_resource_pool, host=destination_host,
                                                         priority=migrate_priority)

        # Wait for task to complete
        self.__wait_task(task)

    def clone_vm(self, destination_datacenter, clone_name, target_resource_pool=None, target_datastore=None):
        # Clone VMs
        # Relocation specifications
        try:
            relocate_destination = vim.vm.RelocateSpec()
            relocate_destination.datastore = target_datastore
            relocate_destination.pool = target_resource_pool
        except AttributeError as e:
            print(e)
            sys.exit(1)

        # root destination folder
        try:
            destination_folder = destination_datacenter.vmFolder
        except AttributeError as e:
            print(e)
            sys.exit(1)

        # Clone Specifications
        try:
            clone_spec = vim.vm.CloneSpec()
            clone_spec.location = relocate_destination
            clone_spec.powerOn = True
            clone_spec.template = False
        except AttributeError as e:
            print(e)
            sys.exit(1)

        # Cloning task
        task = self.this_object_reference.CloneVM_Task(
            folder=destination_folder, name=clone_name, spec=clone_spec)

        # Wait for task to complete
        self.__wait_task(task)

    def clone_vm_by_uuid(self, destination_datacenter, clone_name, vmRef, ramInMb, cpuNumber, hardDiskSizeInByte, target_resource_pool=None, target_datastore=None):
        # Clone VMs
        # Relocation specifications
        try:
            relocate_destination = vim.vm.RelocateSpec()
            relocate_destination.datastore = target_datastore
            relocate_destination.pool = target_resource_pool
        except AttributeError as e:
            print(e)
            sys.exit(1)

        # root destination folder
        try:
            destination_folder = destination_datacenter.vmFolder
        except AttributeError as e:
            print(e)
            sys.exit(1)

        # VM config spec
        try:
            vmconf = vim.vm.ConfigSpec()
            vmconf.numCPUs = int(cpuNumber)
            vmconf.memoryMB = int(ramInMb)
            vmconf.cpuHotAddEnabled = True
            vmconf.memoryHotAddEnabled = True
            for device in vmRef.config.hardware.device:
                if type(device).__name__ == 'vim.vm.device.VirtualDisk':
                    vmHdd = device
            vmHdd.capacityInBytes = int(hardDiskSizeInByte)
            devSpec = vim.vm.device.VirtualDeviceSpec(
                device=vmHdd, operation="edit")
            vmconf.deviceChange.append(devSpec)
            # vmconf.deviceChange = devices
            # numCoresPerSocket
        except AttributeError as e:
            print(e)
            sys.exit(1)

        # Clone Specifications
        try:
            clone_spec = vim.vm.CloneSpec()
            clone_spec.location = relocate_destination
            clone_spec.config = vmconf
            clone_spec.powerOn = True
            clone_spec.template = False

        except AttributeError as e:
            print(e)
            sys.exit(1)

        # Cloning task
        task = vmRef.CloneVM_Task(
            folder=destination_folder, name=clone_name, spec=clone_spec)

        # Wait for task to complete
        resArr = self.__wait_task1(task)
        if(resArr[0] == 'success'):
            return [True, resArr[1].info.result]
        else:
            return [False, None]

    def extendDisk(self):
        path = '[NETAPP_VM_04] lolollol/lolollol.vmdk'
        virtualDiskManager = self.session.content.virtualDiskManager
        task = virtualDiskManager.ExtendVirtualDisk(
            path, None, 83886080, False)

    def search_vm_by_name(self, vm_name):
        # Search for a specific vm by name(not case sensitive), or by patterns with at last 3 characters
        count = 0
        founded_vms_list = []
        vm_name = str(vm_name).strip()
        if len(vm_name) <= 3:
            print("the name provided must be at last 3 characters!")
            return

        print("Begin search...")
        for vms in self.virtual_machines_list:
            vm_name_ref = vms['name']
            if vm_name.lower() in vm_name_ref.lower():
                count += 1
                vm_name_found = vms
                print(vm_name_found)
                founded_vms_list.append(vm_name_found)
        print(" %s virtual machines found using the search criteria." % count)
        if founded_vms_list:
            return founded_vms_list

    def search_vm_by_uuid(self, uuid):
        # Search for a specific vm by UUID
        uuid_found = ""
        for vms in self.virtual_machines_list:
            vm_uuid = vms['uuid']
            if vm_uuid.lower() == uuid.lower():
                uuid_found = vms
        if uuid_found:
            return uuid_found
        else:
            print("virtual machine not found by this UUID!")

    def search_vm_by_ip(self, ip):
        # Search for a specific vm by IP
        ip_found = ""
        for vms in self.virtual_machines_list:
            vm_ip = vms['ip']
            vm_ip = str(vm_ip)
            if vm_ip.lower() == ip.lower():
                ip_found = vms
        if ip_found:
            return ip_found
        else:
            print("virtual machine not found, reason: powered-off or bad vmware-tools")

    def mount_vmware_tools(self):
        # Mount VMware tools
        if self.get_power_state() == "poweredOn":
            print("Power state OK")
            try:
                print("mount vmware tools installer")
                self.this_object_reference.MountToolsInstaller()
            except Exception as err:
                print(err)
        else:
            print("virtual machine is OFF ... powering ON the virtual machine...")
            self.power_on_vm()
            self.mount_vmware_tools()

    def mount_cd(self, datastore_iso_path):
        # Attaching ISO to CD drive
        cd_spec = None
        have_cdrom = False

        # Search for the attached devices to the VM
        if self.__check_reference():
            print("start searching for attached devices...")
            for device in self.this_object_reference.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualCdrom):
                    have_cdrom = True
                    print("CD-ROM Found.")

                    # edit specs
                    cd_spec = vim.vm.device.VirtualDeviceSpec()
                    cd_spec.device = device
                    cd_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit

                    cd_spec.device.backing = vim.vm.device.VirtualCdrom.IsoBackingInfo()

                    # setting the datastore
                    for datastore in self.this_object_reference.datastore:
                        cd_spec.device.backing.datastore = datastore
                        break

                    # edit connectable properties
                    cd_spec.device.backing.fileName = datastore_iso_path
                    cd_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
                    cd_spec.device.connectable.connected = True
                    cd_spec.device.connectable.startConnected = True
                    cd_spec.device.connectable.allowGuestControl = True

            if not have_cdrom:
                print("virtual machine CD-ROM drive not attached!")
                return

            vm_conf = vim.vm.ConfigSpec()
            vm_conf.deviceChange = [cd_spec]

            task = self.this_object_reference.ReconfigVM_Task(vm_conf)

            self.__wait_task(task)

    def delete_vm(self):
        # Destroys the VM, task will remove the files and remove from inventory
        task = self.this_object_reference.Destroy_Task()
        resArr = self.__wait_task1(task)
        if(resArr[0] == 'success'):
            return [True, resArr[1].info.result]
        else:
            return [False, None]

    def reboot_vm(self):
        # reboot the vm
        task = self.this_object_reference.ResetVM_Task()
        self.__wait_task(task)

    def create_vm(self, vm_name, vm_folder, resource_pool, datastore):
        datastore_path = '[' + str(datastore) + '] ' + vm_name
        print("path", datastore_path)

        # bare minimum VM shell, no disks. Feel free to edit
        vmx_file = vim.vm.FileInfo(
            logDirectory=None, snapshotDirectory=None, suspendDirectory=None, vmPathName=datastore_path)
        # print(vmx_file)
        config = vim.vm.ConfigSpec(name=vm_name, memoryMB=128, numCPUs=1,
                                   files=vmx_file, guestId='dosGuest', version='vmx-13')
        # print(config)
        print("Creating VM {}...".format(vm_name))
        vm_folder.CreateVM_Task(config=config, pool=resource_pool)
        # self.__wait_task(task)
        # tasks.wait_for_tasks(service_instance, [task])

    def edit(self, uuid, vm, ram, cpu, hdd):
        vmconf = vim.vm.ConfigSpec()
        vmconf.numCPUs = cpu
        vmconf.memoryMB = ram
        for device in vm.config.hardware.device:
            if type(device).__name__ == 'vim.vm.device.VirtualDisk':
                vm2 = device
        vm2.capacityInBytes = hdd
        devSpec = vim.vm.device.VirtualDeviceSpec(device=vm2, operation="edit")
        vmconf.deviceChange.append(devSpec)
        task = vm.ReconfigVM_Task(spec=vmconf)
        resArr = self.__wait_task1(task)
        if(resArr[0] == 'success'):
            return [True, resArr[1].info.entity]
        else:
            return [False, None]

    def is_valid_ipv4(self, ip):
        """Validates IPv4 addresses.
        """
        pattern = re.compile(r"""
            ^
            (?:
          # Dotted variants:
            (?:
            # Decimal 1-255 (no leading 0's)
                [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
                # Hexadecimal 0x0 - 0xFF (possible leading 0's)
                0x0*[0-9a-f]{1,2}
            |
                0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
            )
            (?:                  # Repeat 0-3 times, separated by a dot
            \.
                (?:
                [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
                |
                0x0*[0-9a-f]{1,2}
                |
                0+[1-3]?[0-7]{0,2}
                )
            ){0,3}
            |
            0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
            |
            0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
            |
          # Decimal notation, 1-4294967295:
            429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
            42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
            4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
            )
            $
        """, re.VERBOSE | re.IGNORECASE)
        return pattern.match(ip) is not None

    def vmAddDisk(self, uuid, size):
        # responseData = {'status':'failure','request_id':request.GET.get('request_id'),'code':400,'propertyName':'add disk','description':'Adds a disk to VM','Message':'Disk Not Added','ReturnData':{'method':'GET','uuid':request.GET.get('uuid')},'error':'Null'}
        # vm_uuid = request.GET.get('uuid')
        vm = self.session.content.searchIndex.FindByUuid(
            None, uuid, True, False)
        task = disk.add_disk(vm, self, size)
        resArr = self.__wait_task1(task)
        if(resArr[0] == 'success'):
            return [True, resArr[1].info.result]
            # responseData.status = 'success'
            # responseData.code = 200
            # return JsonResponse(responseData)
        else:
            # return JsonResponse(responseData)
            return [False, None]

    def vmRemoveDisk(self, uuid, diskNumber):
        # responseData = {'status':'failure','request_id':request.GET.get('request_id'),'code':400,'propertyName':'add disk','description':'Adds a disk to VM','Message':'Disk Not Added','ReturnData':{'method':'GET','uuid':request.GET.get('uuid')},'error':'Null'}
        # vm_uuid = request.GET.get('uuid')
        vm = self.session.content.searchIndex.FindByUuid(
            None, uuid, True, False)
        task = disk.delete_virtual_disk(self, vm, diskNumber)
        resArr = self.__wait_task1(task)
        if(resArr[0] == 'success'):
            return [True, resArr[1].info.result]
            # responseData.status = 'success'
            # responseData.code = 200
            # return JsonResponse(responseData)
        else:
            # return JsonResponse(responseData)
            return [False, None]

    def vmCreateSnapshot(self, uuid, snapshotName):
        vm = self.session.content.searchIndex.FindByUuid(
            None, uuid, True, False)
        task = snapshot.createSnapshot(vm, snapshotName)
        resArr = self.__wait_task1(task)
        if(resArr[0] == 'success'):
            return [True, resArr[1].info.result]
            # responseData.status = 'success'
            # responseData.code = 200
            # return JsonResponse(responseData)
        else:
            # return JsonResponse(responseData)
            return [False, None]


def index(request):
    session = VcenterApiWrapper("", "", "")
    l = []
    # for i in session.virtual_machines_list:
    #     if(i['reference'].config.template):
    #         l.append(i)
    # vm_json = json.dumps(session.virtual_machines_list);

    return HttpResponse(session.virtual_machines_list)


def powerOn(request):
    session = VcenterApiWrapper("", "", "")
    state = False
    vm = session.session.content.searchIndex.FindByUuid(
        None, request.GET.get('uuid'), True, False)
    state = session.power_on_vm_uuid(vm)
    if(state[0]):
        responseData = {'status': 'success', 'request_id': request.GET.get('request_id'), 'code': 200, 'propertyName': 'on', 'description': 'Turns On a VM', 'Message': 'VM Turned On', 'ReturnData': {
            'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'Null'}
        session.disconect()
        return JsonResponse(responseData)
    else:
        responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'on', 'description': 'Turns On a VM', 'Message': 'VM didn\'t turn On', 'ReturnData': {
            'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'Null'}
        session.disconect()
        return JsonResponse(responseData)


def powerOff(request):
    session = VcenterApiWrapper("", "", "")
    state = False
    vm = session.session.content.searchIndex.FindByUuid(
        None, request.GET.get('uuid'), True, False)
    state = session.power_off_vm_uuid(vm)
    if(state[0]):
        responseData = {'status': 'success', 'request_id': request.GET.get('request_id'), 'code': 200, 'propertyName': 'off', 'description': 'Turns Off a VM', 'Message': 'VM Turned Off', 'ReturnData': {
            'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'Null'}
        session.disconect()
        return JsonResponse(responseData)
    else:
        responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'off', 'description': 'Turns Off a VM', 'Message': 'VM Didn\'t turn Off', 'ReturnData': {
            'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'Null'}
        session.disconect()
        return JsonResponse(responseData)


def clone(request):
    session = VcenterApiWrapper("", "", "")
    for i in session.resource_pools_list:
        if i['parent'] == 'HP':
            resource_pool = i['reference']

    config = request.GET.get('config').split("_")
    ram = (int(config[0])*1024)
    cpu = config[1]
    hdd = (int(config[2])*1024*1024*1024)
    datacenter = session.datacenters[0]['reference']
    folder = datacenter.vmFolder
    datastore_reference = None
    dstores = ['NETAPP_VM_06_CLOUDTESTING', 'NETAPP_VM_09', 'NETAPP_VM_10']
    # dstores = ['NETAPP_FC53','NETAPP_FC54']
    for i in session.datastores:
        if(i['name'] in dstores):
            print(i['name'])
            uncommitted = i['reference'].summary.uncommitted if i['reference'].summary.uncommitted else 0
            provSpace = i['reference'].summary.capacity - \
                i['reference'].summary.freeSpace + uncommitted
            freeSpace = i['reference'].summary.freeSpace
            capacity = i['reference'].summary.capacity
            # print(freeSpace, ">", (0.5*hdd), (provSpace/capacity),"<=2.25")
            freeSpaceInGB = freeSpace / (1024 * 1024 * 1024)
            print("in ds reference")
            print(provSpace)
            print(freeSpace)
            print(capacity)
            print(freeSpace > (.5 * hdd))
            print(provSpace/capacity <= 2.25)
            if (freeSpace >= (0.2 * capacity) and provSpace/capacity <= 4):
                datastore_reference = i['reference']
                break
    if(datastore_reference):
        vm = session.session.content.searchIndex.FindByUuid(
            None, request.GET.get('uuid'), True, False)
        resArr = session.clone_vm_by_uuid(datacenter, request.GET.get(
            'name'), vm, ram, cpu, hdd, resource_pool, datastore_reference)
        if(resArr[0]):
            responseData = {'status': 'success', 'request_id': request.GET.get('request_id'), 'code': 200, 'propertyName': 'clone', 'description': 'Clones VM from a template', 'Message': 'VM Cloned', 'ReturnData': {
                'method': 'GET', 'template': request.GET.get('uuid')}, 'vm': resArr[1].summary.config.uuid, 'error': 'Null'}
            session.disconect()
            return JsonResponse(responseData)
        else:
            responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'clone', 'description': 'Clones VM from a template', 'Message': 'VM didn\'t clone', 'ReturnData': {
                'method': 'GET', 'template': request.GET.get('uuid')}, 'vm': None, 'error': 'Null'}
            session.disconect()
            return JsonResponse(responseData)
    else:
        responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'clone', 'description': 'Clones VM from a template', 'Message': 'VM didn\'t clone', 'ReturnData': {
            'method': 'GET', 'template': request.GET.get('uuid')}, 'vm': None, 'error': 'Datastore Capacity Issue'}
        session.disconect()
        return JsonResponse(responseData)


def edit(request):
    session = VcenterApiWrapper("", "", "")
    vm = session.session.content.searchIndex.FindByUuid(
        None, request.GET.get('uuid'), True, False)
    config = request.GET.get('config').split("_")
    ram = 1024 * int(config[0])
    cpu = int(config[1])
    hdd = int(config[2])*1024*1024*1024
    resArr = session.edit(request.GET.get('uuid'), vm, ram, cpu, hdd)
    if(resArr[0]):
        responseData = {'status': 'success', 'request_id': request.GET.get('request_id'), 'code': 200, 'propertyName': 'reconfigure', 'description': 'Reconfigure VM', 'Message': 'VM Reconfigured', 'ReturnData': {
            'method': 'GET', 'vm': request.GET.get('uuid')}, 'error': 'Null'}
        session.disconect()
        return JsonResponse(responseData)
    else:
        responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'reconfigure', 'description': 'Reconfigure VM', 'Message': 'Not Configured', 'ReturnData': {
            'method': 'GET', 'template': request.GET.get('uuid')}, 'error': 'Null'}
        session.disconect()
        return JsonResponse(responseData)


def checkiftemplate(request):
    session = VcenterApiWrapper("", "", "")
    return HttpResponse(session.getTemplateByUuid(request.GET.get('uuid')).config.template)


def destroy(request):
    session = VcenterApiWrapper("", "", "")
    vm = session.session.content.searchIndex.FindByUuid(
        None, request.GET.get('uuid'), True, False)
    session.this_object_reference = vm
    if session.this_object_reference.summary.runtime.powerState != "poweredOff":
        state = session.power_off_vm_uuid(vm)
        if(state[0]):
            resArr = session.delete_vm()
            # print(resArr[0])
            if(resArr[0]):
                responseData = {'status': 'success', 'request_id': request.GET.get('request_id'), 'code': 200, 'propertyName': 'destroy', 'description': 'Destroys a VM', 'Message': 'VM Destroyed', 'ReturnData': {
                    'method': 'GET'}, 'vm': request.GET.get('uuid'), 'error': 'Null'}
                session.disconect()
                return JsonResponse(responseData)
                # return HttpResponse("Destroyed")
            else:
                responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'destroy', 'description': 'Destroys a VM', 'Message': 'VM Not Destroyed', 'ReturnData': {
                    'method': 'GET'}, 'vm': request.GET.get('uuid'), 'error': 'Null'}
                session.disconect()
                return JsonResponse(responseData)
    else:
        resArr = session.delete_vm()
        if(resArr[0]):
            responseData = {'status': 'success', 'request_id': request.GET.get('request_id'), 'code': 200, 'propertyName': 'destroy', 'description': 'Destroys a VM', 'Message': 'VM Destroyed', 'ReturnData': {
                'method': 'GET'}, 'vm': request.GET.get('uuid'), 'error': 'Null'}
            session.disconect()
            return JsonResponse(responseData)
            # return HttpResponse("Destroyed")
        else:
            responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'destroy', 'description': 'Destroys a VM', 'Message': 'VM Not Destroyed', 'ReturnData': {
                'method': 'GET'}, 'vm': request.GET.get('uuid'), 'error': 'Null'}
            session.disconect()
            return JsonResponse(responseData)


def stats(request):
    responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'stats', 'description': 'stats of vm', 'Message': 'stats not found', 'ReturnData': {
        'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'VM NOT FOUND'}
    try:
        session = VcenterApiWrapper("", "", "")
        vm = session.session.content.searchIndex.FindByUuid(
            None, request.GET.get('uuid'), True, False)
        state = False
        randomPass = None
        # oldPassWord = request.GET.get('oldPass')
        uuid = request.GET.get('uuid')
        os = request.GET.get('os')
        if(request.GET.get('cron') == '1'):
            randomPass = changePassword(session, vm, os)

        # state = session.power_on_vm_uuid(vm)
        print(vm.name)
        if(vm):
            ram_usage = vm.summary.quickStats.guestMemoryUsage
            cpu_usage = float(vm.summary.quickStats.overallCpuUsage)/1000
            storage_used = float(
                vm.guest.disk[0].capacity - vm.guest.disk[0].freeSpace)/1024/1024/1024
            power_state = vm.summary.runtime.powerState
        # ipcheck = vm.summary.guest.ipAddress
            checkName = 0
            checkName = vm.name.find('APDCL')
            ipcheck = None
            for nic in vm.guest.net:
                # addresses = nic.ipConfig.ipAddress
                for ip in nic.ipConfig.ipAddress:
                    if(checkName == -1):
                        if(session.is_valid_ipv4(ip.ipAddress) and ip.ipAddress.split(".")[0] != '192' and ip.ipAddress.split(".")[0] != '10'):
                            ipcheck = ip.ipAddress
                    else:
                        if(session.is_valid_ipv4(ip.ipAddress) and ip.ipAddress.split(".")[0] != '10'):
                            ipcheck = ip.ipAddress

            if(ipcheck is not None):
                ip = ipcheck
            else:
                ip = None
            # print(vm.summary)
            session.disconect()
            # responseData = {'status':'success','request_id':request.GET.get('request_id'),'code':200,'propertyName':'stats','description':'Stats On a VM','Message':'Stats','ReturnData':{'method':'GET','uuid':request.GET.get('uuid'),'ram_usage':ram_usage,'cpu_usage':cpu_usage,'storage_used':storage_used, 'power_state':power_state,'ip':ip, 'password':randomPass},'error':'Null'}
            returnDataJSON = {'method': 'GET', 'uuid': request.GET.get(
                'uuid'), 'ram_usage': ram_usage, 'cpu_usage': cpu_usage, 'storage_used': storage_used, 'power_state': power_state, 'ip': ip, 'password': randomPass}
            responseData['status'] = 'success'
            responseData['code'] = 200
            responseData['ReturnData'] = returnDataJSON
            responseData['error'] = 'Null'
            responseData['Message'] = 'stats found'
            return JsonResponse(responseData)
        else:
            session.disconect()
            # responseData = {'status':'failure','request_id':request.GET.get('request_id'),'code':400,'propertyName':'stats','description':'NOT FOUND VM','Message':'VM Not found','ReturnData':{'method':'GET','uuid':request.GET.get('uuid')},'error':'VM NOT FOUND'}
            return JsonResponse(responseData)
    except Exception as e:
        try:
            if(session):
                session.disconect()
        except Exception as ee:
            print(ee)
            pass
        responseData['error'] = str(e)
        return JsonResponse(responseData)


def changePassword(session, vm, os, oldPass=None, username=None):
    randomPass = ''.join(random.choices(
        string.ascii_uppercase + string.ascii_lowercase + string.digits, k=11))
    randomPass = randomPass + "@"
    if((oldPass == None) and (username == None)):
        if(os.lower().find('windows') != -1):
            username = "administrator"
            oldPass = "CYF@123148"
            filePath = "C:\\Users\\Administrator\\Desktop\\cp.bat"
            fileinmemory = "net user administrator %1"
            args = 1
        else:
            username = "root"
            oldPass = "Change@123100"
            filePath = "/home/cp.sh"
            temp = randomPass+"\\n"+randomPass
            fileinmemory = 'echo -e "' + temp + '" | passwd'
            args = 0
    else:
        if(os.lower().find('windows') != -1):
            username = username
            filePath = "C:\\Users\\Administrator\\Desktop\\cp.bat"
            fileinmemory = "net user administrator %1"
            args = 1
        else:
            username = username
            filePath = "/home/cp.sh"
            temp = randomPass+"\\n"+randomPass
            fileinmemory = 'echo -e "' + temp + '" | passwd'
            args = 0

    oldPassWord = oldPass

    session.this_object_reference = vm
    content = session.session.RetrieveContent()
    creds = vim.vm.guest.NamePasswordAuthentication(
        username=username, password=oldPassWord)
    try:
        file_attribute = vim.vm.guest.FileManager.FileAttributes()
        url = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(
            session.this_object_reference, creds, filePath, file_attribute, len(fileinmemory), True)
        url = re.sub(r"^https://\*:", "", url)
        resp = requests.put(url, data=fileinmemory, verify=False)
        if not resp.status_code == 200:
            print("Error while uploading file")
        else:
            print("Successfully uploaded file")
    except Exception as e:
        print(e)
        raise e
    # # Change Windows PAssword
    # content = session.session.RetrieveContent()
    tools_status = session.this_object_reference.guest.toolsStatus
    # print(tools_status)
    # creds = vim.vm.guest.NamePasswordAuthentication(username='administrator', password=oldPassWord)
    try:
        pm = content.guestOperationsManager.processManager
        if(args == 1):
            ps = vim.vm.guest.ProcessManager.ProgramSpec(
                programPath=filePath, arguments=randomPass)
        else:
            ps = vim.vm.guest.ProcessManager.ProgramSpec(
                programPath=filePath, arguments="")
        res = pm.StartProgramInGuest(
            vm=session.this_object_reference, auth=creds,  spec=ps)
        print(res)
        return randomPass
    except Exception as err:
        print(err)
        raise err


def StatCheck(perf_dict, counter_name):
    counter_key = perf_dict[counter_name]
    return counter_key


def BuildQuery(content, vchtime, counterId, instance, vm, interval):
    perfManager = content.perfManager
    metricId = vim.PerformanceManager.MetricId(
        counterId=counterId, instance=instance)

    startTime = vchtime - timedelta(minutes=(interval + 1))
    endTime = vchtime - timedelta(minutes=1)
    query = vim.PerformanceManager.QuerySpec(intervalId=20, entity=vm, metricId=[metricId], startTime=startTime,
                                             endTime=endTime)
    perfResults = perfManager.QueryPerf(querySpec=[query])
    if perfResults:
        return perfResults
    else:
        print('ERROR: Performance results empty.  TIP: Check time drift on source and vCenter server')
        print('Troubleshooting info:')
        print('vCenter/host date and time: {}'.format(vchtime))
        print('Start perf counter time   :  {}'.format(startTime))
        print('End perf counter time     :  {}'.format(endTime))
        print(query)
        exit()


def networkStats(request):
    response = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'networkStats', 'description': 'Network Stats Of a VM', 'Message': 'Network Stats Not Found', 'ReturnData': {
        'method': 'GET', 'uuid': request.GET.get('uuid'), 'downloaded': 0, 'uploaded': 0}, 'error': 'Null'}
    try:
        session = VcenterApiWrapper("", "", "")
        vm_uuid = request.GET.get('uuid')
        vm = session.session.content.searchIndex.FindByUuid(
            None, vm_uuid, True, False)
        content = session.session.RetrieveContent()

        vchtime = session.session.CurrentTime()
        perf_dict = {}
        perfList = content.perfManager.perfCounter
        for counter in perfList:
            counter_full = "{}.{}.{}".format(
                counter.groupInfo.key, counter.nameInfo.key, counter.rollupType)
            perf_dict[counter_full] = counter.key

        interval = 61
        statInt = interval
        summary = vm.summary
        disk_list = []
        network_list = []
        # network usage avg
        statNetworkTx = BuildQuery(content, vchtime, (StatCheck(
            perf_dict, 'net.transmitted.average')), "", vm, interval)
        networkTx = (
            float(sum(statNetworkTx[0].value[0].value) * 8 / 1024) / statInt)
        statNetworkRx = BuildQuery(content, vchtime, (StatCheck(
            perf_dict, 'net.received.average')), "", vm, interval)
        networkRx = (
            float(sum(statNetworkRx[0].value[0].value) * 8 / 1024) / statInt)
        print(len(statNetworkRx[0].sampleInfo))
        print(len(statNetworkRx[0].value[0].value))
        d = {}
        u = {}
        for i in range(len(statNetworkRx[0].value[0].value)):
            u[str(statNetworkTx[0].sampleInfo[i].timestamp)
              ] = statNetworkTx[0].value[0].value[i]
            d[str(statNetworkRx[0].sampleInfo[i].timestamp)
              ] = statNetworkRx[0].value[0].value[i]
            # print(statNetworkRx[0].sampleInfo.timestamp,"->",statNetworkRx[0].value[0].value[i])
            # print(statNetworkTx[0].sampleInfo[i].timestamp,"->",statNetworkTx[0].value[0].value[i],"       ",statNetworkRx[0].sampleInfo[i].timestamp,"->",statNetworkRx[0].value[0].value[i])
        # downloaded = 0;
        # uploaded = 0;
        # for i in range(len(statNetworkRx[0].value[0].value)):
        #     downloaded = downloaded + statNetworkRx[0].value[0].value[i]*20;
        #     uploaded = uploaded + statNetworkTx[0].value[0].value[i]*20
        # print("received packets   "  , (downloaded)/(1024*1024),"GB" )
        # print("transmiited packets   "  , (uploaded)/(1024*1024),"GB")
        response['status'] = 'success'
        response['code'] = 200
        response['Message'] = 'Network stats found'
        response['ReturnData']['downloaded'] = d
        response['ReturnData']['uploaded'] = u
        session.disconect()
        return JsonResponse(response)

    except Exception as e:
        try:
            if(session):
                session.disconect()
        except Exception as ee:
            print(ee)
            pass
        response['error'] = str(e)
        return JsonResponse(response)


def addDisk(request):
    responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'add disk', 'description': 'Adds a disk to VM', 'Message': 'Disk Not Added', 'ReturnData': {
        'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'Null'}
    session = VcenterApiWrapper("", "", "")
    # vm_uuid = request.GET.get('uuid')
    # self.add_disk(vm, session, request.GET.get('size'))
    resArr = session.vmAddDisk(
        request.GET.get('uuid'), request.GET.get('size'))
    if(resArr[0] == True):
        session.disconect()
        # return [True,resArr[1].info.result]
        responseData['status'] = 'success'
        responseData['code'] = 200
        responseData['Message'] = "Disk Added"
        return JsonResponse(responseData)
    else:
        session.disconect()
        return JsonResponse(responseData)
        # return [False, None]


def removeDisk(request):
    responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'Remove disk', 'description': 'Removes a disk of VM', 'Message': 'Disk Not Removed', 'ReturnData': {
        'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'Null'}
    session = VcenterApiWrapper("", "", "")
    # vm_uuid = request.GET.get('uuid')
    # self.add_disk(vm, session, request.GET.get('size'))
    resArr = session.vmRemoveDisk(request.GET.get(
        'uuid'), request.GET.get('diskNumber'))
    if(resArr[0] == True):
        session.disconect()
        # return [True,resArr[1].info.result]
        responseData['status'] = 'success'
        responseData['code'] = 200
        responseData['Message'] = "Disk Removed"
        return JsonResponse(responseData)
    else:
        session.disconect()
        return JsonResponse(responseData)
        # return [False, None]


def addSnapshot(request):
    responseData = {'status': 'failure', 'request_id': request.GET.get('request_id'), 'code': 400, 'propertyName': 'Create Snapshot', 'description': 'Creates a Snapshot', 'Message': 'Snapshot Not Created', 'ReturnData': {
        'method': 'GET', 'uuid': request.GET.get('uuid')}, 'error': 'Null'}
    session = VcenterApiWrapper("", "", "")
    resArr = session.vmCreateSnapshot(request.GET.get(
        'uuid'), request.GET.get('snapshotName'))
    if(resArr[0] == True):
        session.disconect()
        # return [True,resArr[1].info.result]
        responseData['status'] = 'success'
        responseData['code'] = 200
        responseData['Message'] = "Snapshot Created"
        return JsonResponse(responseData)
    else:
        session.disconect()
        return JsonResponse(responseData)
        # return [False, None]


