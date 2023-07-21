import algorithm.data_processing as dp

# Example usage:
filename = 'Full_FYP_crawled_edit.csv'
start_year = '2000'
end_year = '2021'

year_country_counts = dp.count_countries_by_year_range(filename, start_year, end_year)
dp.plot_ransomware_attacks(year_country_counts)