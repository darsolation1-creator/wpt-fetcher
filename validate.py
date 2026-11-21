import asyncio, sys, traceback
sys.path.insert(0, ".")
import wptglobal

async def main():
    try:
        tournaments = await wptglobal.fetch_wpt_tournaments()
    except Exception as e:
        print("FETCH EXCEPTION:", e); traceback.print_exc(); return
    print(f"FETCHED {len(tournaments)} tournaments")
    shown = 0
    for t in tournaments:
        try:
            d = wptglobal._map_tournament(t)
        except Exception as e:
            continue
        if not d:
            continue
        print(f"  - {str(d.get('name'))[:45]:45} | bi={d.get('buy_in')} | players={d.get('players')} | pool={d.get('prize_pool')} | reg_s={d.get('reg_seconds')}")
        shown += 1
        if shown >= 10:
            break
    print(f"MAPPED-OK sample: {shown}")

asyncio.run(main())
