import streamlit as st

st.title("Byte-O-Saurus")

st.write("Protect your Workstation from malware with Byte-o-Saurus! Upload any file or paste any URL and our web app will scan it for threats. Fast, secure, and easy to use. Stop malware in its tracks! Try Byte-o-Saurus today!")

st.file_uploader(label="Upload any exe file")
st.button(label="Submit")

st.text("Or")

st.text_input(label="Paste any link here")
st.button(label="Scan")

st.error("It is malicious")
st.success("It is safe")