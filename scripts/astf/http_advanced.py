from trex.astf.api import *
import argparse


class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self):
        # program
        # Client program taken from client side of given file
        my_prog_c = ASTFProgram(file="../cap2/http_get.pcap", side="c")
        # Server program taken from server side of given file
        my_prog_s = ASTFProgram(file="../cap2/http_get.pcap", side="s")

        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["17.0.0.0", "17.0.0.255"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["49.0.0.0", "49.0.255.255"], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)
        print("\nip_gen_c = {}".format(ip_gen_c.to_json()))
        print("ip_gen_s = {}".format(ip_gen_s.to_json()))
        print("ip_gen = {}".format(ip_gen.to_json()))

        ip_gen_c2 = ASTFIPGenDist(ip_range=["21.0.0.0", "21.0.0.255"], distribution="seq")
        ip_gen_s2 = ASTFIPGenDist(ip_range=["51.0.0.0", "51.0.255.255"], distribution="seq")
        ip_gen2 = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                            dist_client=ip_gen_c2,
                            dist_server=ip_gen_s2)
        print("\nip_gen_c2 = {}".format(ip_gen_c2.to_json()))
        print("ip_gen_s2 = {}".format(ip_gen_s2.to_json()))
        print("ip_gen2 = {}".format(ip_gen2.to_json()))
        
        # template
        temp_c = ASTFTCPClientTemplate(program=my_prog_c,  ip_gen=ip_gen)
        temp_c2 = ASTFTCPClientTemplate(program=my_prog_c, ip_gen=ip_gen2, port=81)
        print("\ntemp_c = {}".format(temp_c.to_json()))
        print("temp_c2 = {}".format(temp_c2.to_json()))

        temp_s = ASTFTCPServerTemplate(program=my_prog_s,)  # using default association
        temp_s2 = ASTFTCPServerTemplate(program=my_prog_s, assoc=ASTFAssociationRule(port=81))
        print("\ntemp_s = {}".format(temp_s.to_json()))
        print("temp_s2 = {}".format(temp_s2.to_json()))
        
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)
        template2 = ASTFTemplate(client_template=temp_c2, server_template=temp_s2)
        print("\ntemplate = {}".format(template.to_json()))
        print("template2 = {}".format(template2.to_json()))
        
        # profile
        profile = ASTFProfile(default_ip_gen=ip_gen, templates=[template, template2])
        print("\nprofile = {}\n ".format(profile.to_json()))
        
        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        args = parser.parse_args(tunables)
        return self.create_profile()


def register():
    return Prof1()
