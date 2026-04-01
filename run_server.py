import os

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

import app


def main():
    app.init_database_safely()
    app.db_instance.init_database()
    app.create_translation_files()
    app.ensure_database_columns()
    app.app.run(debug=False, host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()

