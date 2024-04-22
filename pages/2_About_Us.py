import streamlit as st
from streamlit_card import card
st.set_page_config(page_title="Byte-O-Saurus")

st.title("About us...",anchor=False)
st.write("This project is bonafide work of")


res = card(
    title="Rajaram Walavalkar",
    text="Roll No. 25115",
    styles={
        "card": {
            "width": "100%",
            "height": "100px",
            "border-radius": "6px",
            "margin":"0",
            "background-color":"#262730",
        },
        "text": {
            "font-family": "serif",
        }
    }
)
res2 = card(
    title="Shoiab Shaikh",
    text="Roll No. 25088",
    styles={
        "card": {
            "width": "100%",
            "height": "100px",
            "border-radius": "6px",
            "margin":"0",
            "background-color":"#262730",
        },
        "text": {
            "font-family": "serif",
        }
    }
)
res3 = card(
    title="Mangu",
    text="Roll No. 25109",
    styles={
        "card": {
            "width": "100%",
            "height": "100px",
            "border-radius": "6px",
            "margin":"0",
            "background-color":"#262730",
        },
        "text": {
            "font-family": "serif",
        }
    }
)