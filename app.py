import streamlit as st
import numpy
import pefile
import os
import array
import math
import pickle
import joblib
import warnings

class PEChecker:
    #For calculating the entropy
    def get_entropy(self, data):
        if len(data) == 0:
            return 0.0
        occurences = array.array('L', [0]*256)
        for x in data:
            occurences[x if isinstance(x, int) else ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)

        return entropy

    #For extracting the resources part
    def get_resources(self, pe):
        """Extract resources :
        [entropy, size]"""
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    size = resource_lang.data.struct.Size
                                    entropy = self.get_entropy(data)

                                    resources.append([entropy, size])
            except Exception as e:
                return resources
        return resources

    #For getting the version information
    def get_version_info(self, pe):
        """Return version infos"""
        res = {}
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        res[entry[0]] = entry[1]
            if fileinfo.Key == 'VarFileInfo':
                for var in fileinfo.Var:
                    res[var.entry.items()[0][0]] = var.entry.items()[0][1]
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
            res['os'] = pe.VS_FIXEDFILEINFO.FileOS
            res['type'] = pe.VS_FIXEDFILEINFO.FileType
            res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
            res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
            res['signature'] = pe.VS_FIXEDFILEINFO.Signature
            res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
        return res

    #extract the info for a given file using pefile
    def extract_infos(self, fpath):
        res = {}
        pe = pefile.PE(fpath)
        res['Machine'] = pe.FILE_HEADER.Machine
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristics'] = pe.FILE_HEADER.Characteristics
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        try:
            res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
        except AttributeError:
            res['BaseOfData'] = 0
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        # Sections
        res['SectionsNb'] = len(pe.sections)
        entropy = list(map(lambda x:x.get_entropy(), pe.sections))
        res['SectionsMeanEntropy'] = sum(entropy)/float(len((entropy)))
        res['SectionsMinEntropy'] = min(entropy)
        res['SectionsMaxEntropy'] = max(entropy)
        raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
        res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len((raw_sizes)))
        res['SectionsMinRawsize'] = min(raw_sizes)
        res['SectionsMaxRawsize'] = max(raw_sizes)
        virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
        res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
        res['SectionsMinVirtualsize'] = min(virtual_sizes)
        res['SectionMaxVirtualsize'] = max(virtual_sizes)

        #Imports
        try:
            res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
            res['ImportsNb'] = len(imports)
            res['ImportsNbOrdinal'] = 0
        except AttributeError:
            res['ImportsNbDLL'] = 0
            res['ImportsNb'] = 0
            res['ImportsNbOrdinal'] = 0

        #Exports
        try:
            res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except AttributeError:
            # No export
            res['ExportNb'] = 0
        #Resources
        resources= self.get_resources(pe)
        res['ResourcesNb'] = len(resources)
        if len(resources)> 0:
            entropy = list(map(lambda x:x[0], resources))
            res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
            res['ResourcesMinEntropy'] = min(entropy)
            res['ResourcesMaxEntropy'] = max(entropy)
            sizes = list(map(lambda x:x[1], resources))
            res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
            res['ResourcesMinSize'] = min(sizes)
            res['ResourcesMaxSize'] = max(sizes)
        else:
            res['ResourcesNb'] = 0
            res['ResourcesMeanEntropy'] = 0
            res['ResourcesMinEntropy'] = 0
            res['ResourcesMaxEntropy'] = 0
            res['ResourcesMeanSize'] = 0
            res['ResourcesMinSize'] = 0
            res['ResourcesMaxSize'] = 0

        # Load configuration size
        try:
            res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError:
            res['LoadConfigurationSize'] = 0


        # Version configuration size
        try:
            version_infos = self.get_version_info(pe)
            res['VersionInformationSize'] = len(version_infos.keys())
        except AttributeError:
            res['VersionInformationSize'] = 0
        return res

    def submit(self, fpath, fname):
        #Loading the classifier.pkl and features.pkl
        clf = joblib.load('Classifier/classifier.pkl')
        features = pickle.loads(open(os.path.join('Classifier/features.pkl'),'rb').read())
        
        #extracting features from the PE file mentioned in the argument 
        data = self.extract_infos(fpath)
        
        #matching it with the features saved in features.pkl
        pe_features = numpy.array(list(map(lambda x:data[x], features))).reshape(1, -1)

        #prediciting if the PE is malicious or not based on the extracted features
        res= clf.predict(pe_features)
        
        if res[0] == 1:
            st.error(f"{fname} is malicious")
        else:
            st.success(f"{fname} is safe") 

def sanitization(web):
        web = web.lower()
        token = []
        dot_token_slash = []
        raw_slash = str(web).split('/')
        for i in raw_slash:
            raw1 = str(i).split('-')
            slash_token = []
            for j in range(0,len(raw1)):
                raw2 = str(raw1[j]).split('.')
                slash_token = slash_token + raw2
            dot_token_slash = dot_token_slash + raw1 + slash_token
        token = list(set(dot_token_slash)) 
        if 'com' in token:
            token.remove('com')
        return token
        
class URLChecker:
    def check(self, turl):
        urls = []
        urls.append(turl)
        #print (urls)

        # Using whitelist filter as the model fails in many legit cases since the biggest problem is not finding the malicious urls but to segregate the good ones
        whitelist = ['hackthebox.eu','root-me.org','gmail.com', 'classroom.google.com']
        s_url = [i for i in urls if i not in whitelist]

        if turl in whitelist:
            s_url.append(turl)

        #Loading the model
        file = "Classifier/pickel_model.pkl"
        with open(file, 'rb') as f1:  
            lgr = pickle.load(f1)
        f1.close()
        file = "Classifier/pickel_vector.pkl"
        with open(file, 'rb') as f2:  
            vectorizer = pickle.load(f2)
        f2.close()

        #predicting
        x = vectorizer.transform(s_url)
        y_predict = lgr.predict(x)


        for site in whitelist:
            s_url.append(site)
        #print(s_url)

        predict = list()
        if turl in whitelist:
            predict.append('good')
        predict.append(y_predict[0])
        for j in range(0,len(whitelist)):
            predict.append('good')
        if predict[0] == 'good':
            st.success(f"The {turl} is: {str(predict[0])}")
        else:
            st.warning(f"The {turl} is: {predict[0]}")

warnings.filterwarnings("ignore")


peCheck = PEChecker()
urlCheck = URLChecker()

st.title("Byte-O-Saurus")

st.write("Protect your Workstation from malware with Byte-o-Saurus! Upload any file or paste any URL and our web app will scan it for threats. Fast, secure, and easy to use. Stop malware in its tracks! Try Byte-o-Saurus today!")


ufile = st.file_uploader(label="Upload any exe file", type=['exe'])
if ufile is not None:
    with open("temp.exe", "wb") as f:
        f.write(ufile.getbuffer())
    # st.success('File uploaded successfully.')
    ufile.name
    peCheck.submit("temp.exe", ufile.name)

    f.close()
    
st.text("Or")

def scan(turl):
    if turl is not None and turl != '':
        urlCheck.check(turl=turl)

turl = st.text_input(label="Paste any link here")
# st.button(label="Scan", on_click=scan(turl=turl))
st.button(label="Scan", on_click=scan(turl=turl))