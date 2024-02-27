## build a streamlit app to show all the results

# Path: edge-iiot/st_app.py
import io
import pandas as pd
import dill
import streamlit as st
from  helper import data_type
import matplotlib.pyplot as plt
import seaborn as sns

trained_model = dill.load(open('rf_model.dill', 'rb'))

# @st.cache_data(experimental_allow_widgets=True) 
def main():
    
    ## write a front end view for the app
    html_temp = """
    <div style="background-color:tomato;padding:10px">
    <h2 style="color:white;text-align:center;">CyberSecurity Detector!</h2>
    </div>
    """
    ## display the front end aspect
    st.markdown(html_temp,unsafe_allow_html=True)
    
    st.write('This is a simple app to show the results of the predictive maintenance model.')
    
    file = st.file_uploader("Upload file", type=["csv"])
    if file is not None:
        try:
            ## read the uploaded csv file
            
            X = pd.read_csv(file, low_memory=False, dtype=data_type)
            st.subheader('Data')
            st.write(X.head())
        except Exception as e:
            st.write(str(e))

    st.subheader('EDA')
    if st.button('Analyze data'): 
        st.write('Correlations of selected numerical features')
        selected_numerical_features = ['icmp.seq_le', 'icmp.checksum', 'http.content_length', 'tcp.connection.rst', 'tcp.ack', 'mqtt.topic_len']
        correlation_matrix = X[selected_numerical_features].corr()
        fig, ax = plt.subplots()
        sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt='.2f')
        st.pyplot(fig)
        plt.clf()
        
        st.write('Counts of selected categorical features')
        selected_categorical_features = ['mqtt.protoname', 'http.response', 'http.request.method', 'mqtt.conack.flags']
        fig, axes = plt.subplots(2, 2, figsize=(8, 8))
        ax = axes.flat
        fig.subplots_adjust(wspace=0.5)
        for i, col in enumerate(selected_categorical_features):
            sns.countplot(data=X[selected_categorical_features], x=col, ax=ax[i])
        st.pyplot(fig)
        plt.clf() 
  
    st.subheader('Prediction') 
    if st.button('Predict'):
        try:
            st.write('Start predicting')
            predictions = trained_model.predict(X)
            
            st.write('Normal vs. Attack')
            normal_count = (predictions == 'Normal').sum()
            attack_count = len(predictions) - normal_count
            ax = pd.DataFrame({'Normal': [normal_count], 'Attack': [attack_count]}).plot(kind='bar')
            fig = ax.figure
            st.pyplot(fig)
            plt.clf()
            
            st.write('Attack Types')
            ax2 = pd.DataFrame({'Attack_type':predictions}).Attack_type.value_counts().sort_values(ascending=True).plot(kind='barh')
            fig2 = ax2.figure
            st.pyplot(fig2)
            plt.clf()
            

            
            # st.write(cr)
            
        except Exception as e:
            st.write(str(e))
    


if __name__ == '__main__':
    main()
    
    
