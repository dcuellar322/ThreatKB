"""Refresh local GeoIP metadata without changing indicator identity or state."""
import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--yes', action='store_true', help='Apply the displayed metadata updates')
    args = parser.parse_args()
    from app import app, db
    from app.models.c2ip import C2ip
    from app.geo_ip_helper import get_geo_for_ip
    with app.app_context():
        query = C2ip.query
        if not args.force:
            query = query.filter(db.or_(C2ip.asn.is_(None), C2ip.country.is_(None)))
        updates = []
        for indicator in query:
            geo = get_geo_for_ip(indicator.ip)
            if geo.get('asn') or geo.get('country_code'):
                updates.append((indicator.id, geo.get('asn'), geo.get('country_code')))
        print(f'{len(updates)} indicators have available GeoIP updates.')
        if not args.yes:
            print('Run with --yes to apply these updates.')
            return
        for identity, asn, country in updates:
            db.session.execute(db.update(C2ip).where(C2ip.id == identity).values(asn=asn, country=country))
        db.session.commit()


if __name__ == '__main__':
    main()
