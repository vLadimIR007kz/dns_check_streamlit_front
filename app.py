import streamlit as st
from pymongo import MongoClient
import pandas as pd
import matplotlib.pyplot as plt
import ipaddress

# Подключение к MongoDB
client = MongoClient("mongodb://admin:nazarenko@167.114.2.6:27017/")
db = client.ioc_db

# Функция для получения данных по client_id и password
def get_client_data(client_id, password):
    client_info = db.client_list.find_one({"client_id": client_id, "password": password})
    if not client_info:
        return None

    # Извлекаем все IP-адреса для данного client_id
    client_ips = list(db.client_list.find({"client_id": client_id}, {"client_ip": 1}))

    # Преобразуем список словарей в список IP-адресов
    client_ips = [ip['client_ip'] for ip in client_ips]

    requests = list(db.client_request.find({"client_ip": {"$in": client_ips}}))
    return requests, client_ips

# Функция для получения запрещенных категорий для клиента
def get_banned_categories(client_id):
    banned_categories = list(db.client_categories.find({"client_id": client_id}, {"category": 1}))
    categories = [category['category'] for category in banned_categories]

    # Всегда добавляем категорию "malicious"
    categories.append("malicious")
    
    return categories

# Функция для проверки существования IP-адреса
def is_ip_exists(client_id, new_ip):
    existing_ips = db.client_list.find({"client_id": client_id}, {"client_ip": 1})
    return new_ip in [ip['client_ip'] for ip in existing_ips]

# Функция для добавления нового IP-адреса
def add_ip_address(client_id, new_ip, password):
    db.client_list.insert_one({"client_id": client_id, "client_ip": new_ip, "password": password})

# Функция для добавления заблокированной категории
def add_banned_category(client_id, selected_category):
    banned_categories = get_banned_categories(client_id)
    
    # Проверяем, существует ли категория в заблокированных
    if selected_category in banned_categories:
        return False  # Категория уже забанена
    
    db.client_categories.insert_one({"client_id": client_id, "category": selected_category})
    return True  # Успешно добавлено

# Функция для удаления заблокированной категории
def delete_banned_category(client_id, selected_category):
    if selected_category == "malicious":
        return False  # Нельзя удалить категорию malicious

    db.client_categories.delete_one({"client_id": client_id, "category": selected_category})
    return True  # Успешно удалено

# Главная функция Streamlit
def main():
    st.title("Статистика запросов DNS")

    # Проверяем, вошел ли пользователь
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    # Страница логина
    if not st.session_state.logged_in:
        st.subheader("Вход")
        client_id = st.text_input("Client ID")
        password = st.text_input("Password", type="password")

        if st.button("Войти"):
            requests, client_ips = get_client_data(client_id, password)
            if requests is None:
                st.error("Неверный Client ID или пароль.")
            else:
                st.session_state.logged_in = True
                st.session_state.requests = requests  # Сохраняем запросы в сессии
                st.session_state.client_id = client_id  # Сохраняем client_id
                st.session_state.client_ips = client_ips  # Сохраняем IP-адреса
                st.session_state.password = password  # Сохраняем пароль

    # Страница статистики запросов
    else:
        requests = st.session_state.requests
        df = pd.DataFrame(requests)

        # Проверяем, есть ли данные
        if df.empty:
            st.warning("Нет запросов для данного клиента.")
            return

        # Сводная статистика по всем запросам
        st.subheader("Сводная статистика запросов")

        # Круговая диаграмма
        overall_category_counts = df['category'].value_counts()
        fig_overall, ax_overall = plt.subplots()
        ax_overall.pie(overall_category_counts, labels=overall_category_counts.index, autopct='%1.1f%%', startangle=90)
        ax_overall.axis('equal')  # Круговая диаграмма
        st.pyplot(fig_overall)

        # График топ-15 доменов
        top_domains_overall = df['domain'].value_counts().head(15)
        fig_top_overall, ax_top_overall = plt.subplots()
        ax_top_overall.barh(top_domains_overall.index, top_domains_overall.values)
        ax_top_overall.set_xlabel("Количество запросов")
        ax_top_overall.set_title("Топ-15 доменов")
        st.pyplot(fig_top_overall)

        # Отображение статистики по каждому IP-адресу
        for client_ip in st.session_state.client_ips:
            st.subheader(f"Статистика для IP: {client_ip}")

            # Фильтруем запросы по IP
            ip_requests = df[df['client_ip'] == client_ip]

            # Проверяем, есть ли данные для этого IP
            if ip_requests.empty:
                st.warning(f"Нет запросов для IP {client_ip}.")
                continue

            # Круговая диаграмма для IP
            ip_category_counts = ip_requests['category'].value_counts()
            fig_ip, ax_ip = plt.subplots()
            ax_ip.pie(ip_category_counts, labels=ip_category_counts.index, autopct='%1.1f%%', startangle=90)
            ax_ip.axis('equal')  # Круговая диаграмма
            st.pyplot(fig_ip)

            # График топ-15 доменов для IP
            top_domains_ip = ip_requests['domain'].value_counts().head(15)
            fig_ip_top, ax_ip_top = plt.subplots()
            ax_ip_top.barh(top_domains_ip.index, top_domains_ip.values)
            ax_ip_top.set_xlabel("Количество запросов")
            ax_ip_top.set_title(f"Топ-15 доменов для IP {client_ip}")
            st.pyplot(fig_ip_top)

            # Список запросов для IP
            st.subheader("Список всех запросов")
            st.write(ip_requests[['domain', 'category', 'resolved_allowed']])

        # Отображение запрещенных категорий
        banned_categories = get_banned_categories(st.session_state.client_id)
        st.subheader("Запрещенные категории")
        if banned_categories:
            st.write(", ".join(banned_categories))
        else:
            st.write("Нет запрещенных категорий для данного клиента.")

        # Добавление нового IP-адреса
        st.subheader("Добавить новый IP-адрес")
        new_ip = st.text_input("Введите новый IP-адрес")

        # Проверка нажатия кнопки "Добавить"
        if st.button("Добавить IP"):
            try:
                # Валидация IP-адреса
                ipaddress.ip_address(new_ip)

                # Проверка на существование IP-адреса
                if is_ip_exists(st.session_state.client_id, new_ip):
                    st.error("Этот IP-адрес уже существует.")
                else:
                    # Добавление нового IP-адреса в базу данных
                    add_ip_address(st.session_state.client_id, new_ip, st.session_state.password)
                    st.success("IP-адрес добавлен успешно.")

                    # Обновляем запросы и IP-адреса после добавления
                    requests, client_ips = get_client_data(st.session_state.client_id, st.session_state.password)
                    st.session_state.requests = requests
                    st.session_state.client_ips = client_ips

                    # Отладочная информация для проверки обновления
                    st.write("Запросы после добавления нового IP:")
                    st.write(requests)  # Отображаем запросы для проверки

            except ValueError:
                st.error("Введите корректный IP-адрес.")

        # Добавление новой заблокированной категории
        st.subheader("Добавить заблокированную категорию")
        all_categories = list(db.categories.find({}, {"category": 1}))
        categories_list = [category['category'] for category in all_categories]
        
        selected_category = st.selectbox("Выберите категорию", categories_list)

        if st.button("Добавить категорию"):
            if add_banned_category(st.session_state.client_id, selected_category):
                st.success("Категория добавлена успешно.")
            else:
                st.error("Эта категория уже заблокирована.")

        # Удаление заблокированной категории
        st.subheader("Удалить заблокированную категорию")
        banned_categories = get_banned_categories(st.session_state.client_id)
        banned_categories = [cat for cat in banned_categories if cat != "malicious"]  # Исключаем malicious

        if banned_categories:
            selected_banned_category = st.selectbox("Выберите категорию для удаления", banned_categories)

            if st.button("Удалить категорию"):
                if delete_banned_category(st.session_state.client_id, selected_banned_category):
                    st.success("Категория удалена успешно.")
                else:
                    st.error("Нельзя удалить категорию 'malicious'.")
        else:
            st.write("Нет заблокированных категорий для удаления.")

if __name__ == "__main__":
    main()
