import streamlit as st
import pickle

st.set_page_config(page_title="Byte-O-Saurus")
st.title("Byte-O-Saurus")

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

        with st.status("Analyzing") as sts:

            predict = list()
            if turl in whitelist:
                predict.append('good')
            predict.append(y_predict[0])
            for j in range(0,len(whitelist)):
                predict.append('good')
            if predict[0] == 'good':
                st.success(f"The {turl} is: {str(predict[0])}")
                sts.update(label="Safe", expanded=True, state="complete")
            else:
                st.warning(f"The {turl} is: {predict[0]}")
                sts.update(label="Potentially unwanted", expanded=True, state="complete")

urlCheck = URLChecker()

def scan(turl):
    if turl is not None and turl != '':
        urlstring = str(turl).strip()
        surls = urlstring.split(",")
        for url in surls:
            print(url)
            urlCheck.check(turl=url)

turl = st.text_input(label="Paste any link here")
# st.button(label="Scan", on_click=scan(turl=turl))
st.button(label="Scan", on_click=scan(turl=turl.lower()))