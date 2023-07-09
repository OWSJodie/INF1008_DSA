import pandas as pd


def calculate_variable_correlations(df, variables_column, variables_of_interest):
    """
    Calculates correlations for each variable separately based on the provided DataFrame.

    Parameters:
    - df (DataFrame): The input DataFrame containing the data.
    - variables_column (str): The column name representing the variables.
    - variables_of_interest (list): A list of column names representing the variables of interest.

    Returns:
    - correlation_results (dict): A dictionary containing the correlation matrices for each variable.
    """
    correlation_results = {}
    variables = df[variables_column].dropna().unique()

    for variable in variables:
        variable_df = df[df[variables_column] == variable]
        correlations = variable_df[variables_of_interest].corr()
        correlation_results[variable] = correlations

        print(f"Correlations for Variable: {variable}")
        print(correlations)
        print('\n')

    return correlation_results


# configuration
pd.set_option('display.max_rows', None)  # Set to None to display all rows
pd.set_option('display.max_columns', None)  # Set to None to display all columns

MAP_Mixed_baseSeverity = {
    'HIGH': 10,
    'MEDIUM': 6.5,
    'LOW': 3.5
}

print("Please wait, loading dataframe")
# Assuming your Excel file is named 'filename.xlsx' and contains only one sheet
df = pd.read_excel('../dataset/updated_cve_2023_07_08.xlsx')
print("Complete loading dataframe!")

# Map the value to the words
df['Mixed_baseSeverity'] = df['Mixed_baseSeverity'].map(MAP_Mixed_baseSeverity)

filtered_df = df[
    (df[['Mixed_exploitabilityScore', 'Mixed_impactScore', 'Mixed_baseSeverity', 'Mixed_basedScore']] != 0).all(axis=1)]

# Display the DataFrame
# print("Calculating correlation!")
# pearson_corr = filtered_df[
#     ['Mixed_exploitabilityScore', 'Mixed_impactScore', 'Mixed_baseSeverity', 'Mixed_basedScore']].corr(method='pearson')
# print("Pearson correlation:", pearson_corr)





# Assuming df is your DataFrame and 'vendor' is the column representing vendors
variables_of_interest = ['Mixed_exploitabilityScore', 'Mixed_impactScore', 'Mixed_baseSeverity', 'Mixed_basedScore']
results = calculate_variable_correlations(df, 'vulnerability', variables_of_interest)

# Access the correlation results for all vendor
print(results)

# Access the correlation results for a specific vendor
#print(results['redhat'])