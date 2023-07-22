import ast

import pandas as pd
import numpy as np
from collections import Counter
import algorithm.config as config
import plotly.express as px
import plotly.graph_objects as go
import csv
import algorithm.config as config
import plotly.graph_objs as go
import plotly.io as pio


def load_data(filename):
    """
    Load the data from the csv file.

    Parameters:
    - filename (str): The path to the csv file.

    Returns:
    - df (pandas.DataFrame): The DataFrame containing the data.
    """

    df = pd.read_csv(filename, dtype=str, low_memory=False)
    return df


def map_words_to_values(df, column_name, mapping):
    """
    Map the words in the specified column to values.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - column_name (str): The name of the column to map.
    - mapping (dict): A dictionary that maps words to values.

    Returns:
    - df (pandas.DataFrame): The DataFrame with the words in the specified column mapped to values.
    """
    df[column_name] = df[column_name].map(mapping)
    return df


def convert_xlsx_to_cleaned_csv(filename, file_location):
    """
       Convert an Excel file to a cleaned CSV file.

       Parameters:
       - filename (str): The path to the input Excel file.
       - file_location (str): The path to save the cleaned CSV file.
       """

    df = pd.read_excel(filename)
    # Map the words to values based on the provided mapping
    df = map_words_to_values(df, 'Mixed_baseSeverity', config.MAPPING)

    # List of columns you want to modify
    columns_to_modify = ['Mixed_exploitabilityScore',
                         'Mixed_impactScore',
                         'Mixed_baseSeverity',
                         'Mixed_basedScore']

    # Replace non-numeric values with NaN
    for column in columns_to_modify:
        df[column] = pd.to_numeric(df[column], errors='coerce')

    # Replace NaNs with column means in these columns
    for column in columns_to_modify:
        df[column].fillna(df[column].mean(), inplace=True)

    df.to_csv(file_location, index=False)


def convert_xlsx_to_csv(filename, file_location):
    """
       Convert an Excel file to a CSV file.

       Parameters:
       - filename (str): The path to the input Excel file.
       - file_location (str): The path to save the CSV file.
       """

    df = pd.read_excel(filename)
    df.to_csv(file_location, index=False)

def generate_synthetic_data(df, num_samples=100):
    # Generate synthetic data
    synthetic_data = pd.DataFrame({
        'Mixed_basedScore': np.random.choice(df['Mixed_basedScore'], num_samples),
        'Mixed_exploitabilityScore': np.random.choice(df['Mixed_exploitabilityScore'], num_samples),
        'Mixed_impactScore': np.random.choice(df['Mixed_impactScore'], num_samples),
        'Mixed_obtainPrivilege': np.random.choice(df['Mixed_obtainPrivilege'], num_samples),
        'Mixed_userInteractionRequired': np.random.choice(df['Mixed_userInteractionRequired'], num_samples),
    })

    return synthetic_data

def analyze_attack_types_time_series(df, frequency='month'):
    """
    Analyze the time series of each unique individual attack.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - frequency (str): The frequency of the time series, either 'month' or 'year'.

    Returns:
    - fig (plotly.graph_objects.Figure): The figure containing the plot.
    """

    # Convert the 'cve_published_date' column to the appropriate date format
    df['cve_published_date'] = pd.to_datetime(df['cve_published_date'], format='%d/%m/%Y')

    # Function to clean the attack_type values and extract individual attack types
    def clean_attack_types(types):
        if isinstance(types, str):
            types_list = ast.literal_eval(types)
            cleaned_types = [t.strip('[]\'"') for t in types_list]
            return cleaned_types
        else:
            return []

    # Clean the 'attack_type' column and create a new column with cleaned attack types
    df['cleaned_attack_type'] = df['attack_type'].apply(clean_attack_types)

    # Get unique attack types and concatenate them into a single set
    unique_attack_types_set = set()
    _ = df['cleaned_attack_type'].apply(lambda x: unique_attack_types_set.update(x))

    # Create a list of line traces
    traces = []

    # Create a trace for each unique attack type and add it to the traces list
    for attack_type in unique_attack_types_set:
        df_filtered = df[df['cleaned_attack_type'].apply(lambda x: attack_type in x)]
        if frequency == 'month':
            time_series = df_filtered.groupby(pd.Grouper(key='cve_published_date', freq='M')).size()
        elif frequency == 'year':
            time_series = df_filtered.groupby(pd.Grouper(key='cve_published_date', freq='Y')).size()
        else:
            raise ValueError("Invalid frequency parameter. Use 'month' or 'year'.")

        trace = go.Scatter(
            x=time_series.index,
            y=time_series.values,
            mode='lines',
            name=attack_type
        )
        traces.append(trace)

        layout = go.Layout(
            title='Number of Vulnerabilities over Time',
            xaxis=dict(title='Date', automargin=True),
            yaxis=dict(title='Number of Vulnerabilities', automargin=True),
            showlegend=True,
        )

        # Create the figure
        fig = go.Figure(data=traces, layout=layout)


    return fig

def analyze_attack_types_by_vendor(df):
    """
    Analyze the attack types by vendor.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.

    Returns:
    - fig (plotly.graph_objects.Figure): The figure containing the plot.
    """

    # Convert the 'cve_published_date' column to the appropriate date format
    df['cve_published_date'] = pd.to_datetime(df['cve_published_date'], format='%d/%m/%Y')

    # Function to clean the attack_type values and extract individual attack types
    def clean_attack_types(types):
        if isinstance(types, str):
            types_list = ast.literal_eval(types)
            cleaned_types = [t.strip('[]\'"') for t in types_list]
            return cleaned_types
        else:
            return []

    # Clean the 'attack_type' column and create a new column with cleaned attack types
    df['cleaned_attack_type'] = df['attack_type'].apply(clean_attack_types)

    # Get unique attack types and concatenate them into a single set
    unique_attack_types_set = set()
    _ = df['cleaned_attack_type'].apply(lambda x: unique_attack_types_set.update(x))

    # Get unique vendors
    unique_vendors = df['vendor'].unique()

    # Create the layout
    layout = go.Layout(
        title='CVEs Time Series for Different Attacks on Vendor',
        xaxis=dict(title='Date', automargin=True),
        yaxis=dict(title='Vendor', automargin=True),
        showlegend=True,
    )

    # Create the figure
    fig = go.Figure(layout=layout)

    # Create a trace for each unique attack type and add it to the figure
    for attack_type in unique_attack_types_set:
        df_filtered = df[df['cleaned_attack_type'].apply(lambda x: attack_type in x)]
        fig.add_trace(go.Scatter(
            x=df_filtered['cve_published_date'],
            y=df_filtered['vendor'],
            mode='markers',
            marker=dict(size=8, opacity=0.7),
            name=attack_type
        ))

    # Return the figure
    return fig

def count_countries_by_year_range(filename, start_year, end_year):
    """
    Count the occurrences of countries within a specified year range.

    Parameters:
    - filename (str): The path to the input CSV file.
    - start_year (str): The starting year of the range.
    - end_year (str): The ending year of the range.

    Returns:
    - year_country_counts (dict): A dictionary containing the counts of countries for each year within the range.
    """

    with open(filename, 'r', newline='', encoding='utf-8', errors= 'ignore') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)  # Read the header row

        date_index = header.index('Year')
        country_index = header.index('Country')

        year_country_counts = {}

        for row in reader:
            date = row[date_index]
            year = date.split('-')[0]  # Extract the year from the date

            if start_year <= year <= end_year:
                country = row[country_index]
                if year in year_country_counts:
                    if country in year_country_counts[year]:
                        year_country_counts[year][country] += 1
                    else:
                        year_country_counts[year][country] = 1
                else:
                    year_country_counts[year] = {country: 1}

        return year_country_counts

def plot_ransomware_attacks(result):

    """
    Plot the number of ransomware attacks over the years by countries.

    Parameters:
    - result (dict): A dictionary containing the counts of ransomware attacks by countries.

    Returns:
    - fig (plotly.graph_objects.Figure): The figure containing the plot.
    """


    # Convert the result into a DataFrame
    df = pd.DataFrame(result).T
    df_sorted = df.sort_index(ascending=False)

    # Create a plotly figure
    fig = go.Figure()

    # Add a bar for each country
    for country in df_sorted.columns:
        fig.add_trace(
            go.Bar(
                x=df_sorted.index,
                y=df_sorted[country],
                name=country
            )
        )

    # Update layout
    fig.update_layout(
        title="Ransomware Attacks over the Years by Countries",
        xaxis_title="Year",
        yaxis_title="Number of Ransomware Attacks",
        barmode='stack'
    )

    # Show the figure
    return fig

def top_5_vulnerability_bar_graph(df):

    """
    Plot the top 5 vulnerability types over the years.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.

    Returns:
    - fig (plotly.graph_objects.Figure): The figure containing the plot.
    """

    # Remove rows with missing 'attack_type'
    df = df.dropna(subset=['attack_type'])

    # convert the 'cve_published_date' column to datetime and extract year
    df['cve_published_date'] = pd.to_datetime(df['cve_published_date'], format="%d/%m/%Y")
    df['year'] = df['cve_published_date'].dt.year

    # "explode" the attack_type column (transform each element of a list-like to a row)
    df['attack_type'] = df['attack_type'].apply(ast.literal_eval)
    df = df.explode('attack_type')

    # Now we can group by year and attack_type, and count the frequencies
    attack_counts = df.groupby(['year', 'attack_type']).size().reset_index(name='counts')

    # Sort by counts in descending order and take the top 5 for each year
    top_attacks = attack_counts.groupby('year').apply(lambda x: x.nlargest(5, 'counts')).reset_index(drop=True)

    # Now we can plot the data
    fig = px.bar(top_attacks, x='year', y='counts', color='attack_type', title='Top 5 Vulnerability Over The Years')
    return fig

def top_5_vulnerability_by_vendor(df):

    """
    Plot the top 5 yearly vulnerabilities by vendor.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.

    Returns:
    - fig (plotly.graph_objects.Figure): The figure containing the plot.
    """
    # Remove rows with missing 'vendor'
    df = df.dropna(subset=['vendor'])

    # Convert the 'cve_published_date' column to datetime and extract year
    df['cve_published_date'] = pd.to_datetime(df['cve_published_date'], format="%d/%m/%Y")
    df['year'] = df['cve_published_date'].dt.year

    # Now we can group by year and vendor, and count the frequencies
    vendor_counts = df.groupby(['year', 'vendor']).size().reset_index(name='counts')

    # Sort by counts in descending order and take the top 5 for each year
    top_vendors = vendor_counts.groupby('year').apply(lambda x: x.nlargest(5, 'counts')).reset_index(drop=True)

    # Now we can plot the data
    fig = px.bar(top_vendors, x='year', y='counts', color='vendor', title='Top 5 Yearly Vulnerability by Vendor')

    return fig

# file_location = '../dataset/updated_cve_2023_07_09.xlsx'
# csv_file_location = '../dataset/updated_cve_2023_07_09.csv'
# convert_xlsx_to_cleaned_csv(file_location,csv_file_location)

